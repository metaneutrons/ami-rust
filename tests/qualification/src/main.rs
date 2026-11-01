#![no_main]
//! Bounded native qualification fixture for M1-T03 through M1-T11.
//!
//! The host harness selects one ASCII mode in argument 1. Assertions are
//! represented by native application status and counters, not by text output.
//! A mode pass does not establish overall M1 qualification.
//!
//! Modes cover ABI/callbacks, allocation limits, the M0 churn workload, DOS
//! files, libraries, ports/messages, diagnostics, injected faults, and fatal
//! cleanup. `cleanup-secondary` intentionally returns success with forgotten
//! live resources so native shutdown can test close-error and re-entry paths.

#![no_std]

extern crate alloc;

mod m2;
mod m3;
mod m4;
mod m5;
#[cfg(not(all(target_os = "aros", target_abi = "abi11")))]
#[path = "probe/x86_64_abi1.rs"]
mod probe;
#[cfg(all(target_os = "aros", target_abi = "abi11"))]
#[path = "probe/x86_64_abi11.rs"]
mod probe;
mod stderr;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
    mem, ptr,
};

use aros::{
    AppStatus, BytePath, Context, Device, Error, ErrorKind, File, FileMode, Library, Message, Port,
    Request, RequestKind, Signal, wait_signals,
};
use aros_sys::{self as sys, SdkError, SdkStats};

const CALLBACK_SENTINEL: u64 = 0x4152_4f53_5255_5354;
const M0_SEED: u32 = 0x4152_4f53;
const MAX_IO_SIZE: usize = 1024 * 1024;
const FAULT_ALLOC: u32 = 1;
const FAULT_OPEN: u32 = 2;
const FAULT_READ: u32 = 3;
const FAULT_WRITE: u32 = 4;
const FAULT_CLOSE: u32 = 5;
const FAULT_OPEN_LIBRARY: u32 = 6;
const FAULT_ALLOC_SIGNAL: u32 = 7;
const FAULT_CREATE_PORT: u32 = 8;
const FAULT_SLOT_RESERVATION: u32 = 9;
const FAULT_SHORT_READ: u32 = 10;
const FAULT_SHORT_WRITE: u32 = 11;
const FAULT_ZERO_WRITE: u32 = 12;
const FAULT_SECONDARY_FATAL: u32 = 14;
const FAULT_OPEN_DEVICE: u32 = 16;

const FILE_CASES: [(&[u8], usize); 6] = [
    (b"RAM:ami-rust-m1/fixture-0.bin", 0),
    (b"RAM:ami-rust-m1/fixture-1.bin", 1),
    (b"RAM:ami-rust-m1/fixture-64.bin", 64),
    (b"RAM:ami-rust-m1/fixture-4096.bin", 4096),
    (b"RAM:ami-rust-m1/fixture-1048576.bin", MAX_IO_SIZE),
    (b"RAM:ami-rust-m1/file with spaces.bin", MAX_IO_SIZE),
];

unsafe extern "C" {
    fn sdk_test_fault(site: u32, nth: u32);
    fn sdk_test_reset_fault();
    fn sdk_test_slot_limit(limit: u64);
}

fn mode(context: &Context) -> Option<&str> {
    core::str::from_utf8(context.args().nth(1)?).ok()
}

fn report_error(context: &Context, error: Error) {
    let class_and_operation = ((error.kind_code() as u64) << 8) | (error.operation as u8 as u64);
    context.diagnostic(b"qualification-error-kind-operation", class_and_operation);
    context.diagnostic(b"qualification-native-error", error.native as u64);
}

fn fatal(context: &Context, code: u64) -> AppStatus {
    context.diagnostic(b"qualification-failure", code);
    AppStatus::Fatal
}

fn success(context: &Context, label: &[u8], code: u64) -> AppStatus {
    context.diagnostic(label, code);
    AppStatus::Success
}

fn same_resources(a: SdkStats, b: SdkStats) -> bool {
    a.blocks == b.blocks
        && a.backing_charge == b.backing_charge
        && a.files == b.files
        && a.libraries == b.libraries
        && a.ports == b.ports
        && a.signals == b.signals
        && a.messages == b.messages
        && a.devices == b.devices
        && a.requests == b.requests
        && a.directories == b.directories
        && a.rastports == b.rastports
        && a.bitmaps == b.bitmaps
}

fn one_refusal_since(context: &Context, before: SdkStats) -> bool {
    let after = context.statistics();
    after.refusals == before.refusals + 1 && same_resources(before, after)
}

fn expect_error<T>(context: &Context, result: Result<T, Error>, expected_kind: ErrorKind) -> bool {
    match result {
        Err(error) => {
            report_error(context, error);
            error.kind == expected_kind
        }
        Ok(value) => {
            drop(value);
            false
        }
    }
}

fn expected_raw_error(
    context: &Context,
    error: SdkError,
    expected_kind: ErrorKind,
    operation: aros::Operation,
) -> bool {
    let actual_kind = match error.kind {
        sys::ERROR_KIND_INPUT => ErrorKind::Input,
        sys::ERROR_KIND_LIMIT => ErrorKind::Limit,
        sys::ERROR_KIND_OWNER => ErrorKind::Owner,
        sys::ERROR_KIND_STATE => ErrorKind::State,
        sys::ERROR_KIND_EOF => ErrorKind::Eof,
        sys::ERROR_KIND_ZERO_PROGRESS => ErrorKind::ZeroProgress,
        _ => ErrorKind::Native,
    };
    let converted = Error {
        kind: actual_kind,
        native: error.native,
        operation,
    };
    report_error(context, converted);
    actual_kind == expected_kind
}

fn expect_raw_owner_refusal(
    context: &Context,
    result: i32,
    error: SdkError,
    operation: aros::Operation,
) -> bool {
    result == -1
        && error.kind == sys::ERROR_KIND_OWNER
        && expected_raw_error(context, error, ErrorKind::Owner, operation)
}

fn expect_native_error<T>(context: &Context, result: Result<T, Error>, native: i64) -> bool {
    match result {
        Err(error) => {
            report_error(context, error);
            error.kind == ErrorKind::Native && error.native == native
        }
        Ok(value) => {
            drop(value);
            false
        }
    }
}

fn set_fault(site: u32) {
    // SAFETY: test-only native control; the host harness links this symbol.
    set_fault_nth(site, 1);
}

fn set_fault_nth(site: u32, nth: u32) {
    // SAFETY: test-only native control; the host harness links this symbol.
    unsafe { sdk_test_fault(site, nth) };
}

/// Lowers the native token space so `Limit` exhaustion is reachable without
/// exhausting memory; zero restores the production value.
fn set_slot_limit(limit: u64) {
    // SAFETY: test-only native control; the host harness links this symbol.
    unsafe { sdk_test_slot_limit(limit) };
}

fn reset_fault() {
    // SAFETY: clears only the current one-shot test fault.
    unsafe { sdk_test_reset_fault() };
}

fn byte_path(bytes: &[u8]) -> Option<BytePath> {
    match BytePath::new(bytes) {
        Ok(path) => Some(path),
        Err(_) => None,
    }
}

fn fill_sequence(bytes: &mut [u8], offset: usize) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = offset.wrapping_add(index) as u8;
    }
}

fn make_sequence(length: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(length).is_err() {
        return None;
    }
    bytes.resize(length, 0);
    fill_sequence(&mut bytes, 0);
    Some(bytes)
}

fn abi_and_callbacks(context: &Context) -> bool {
    let expected_layout = sys::layout_values();
    let mut actual_layout = [0u64; sys::ABI_LAYOUT_VALUE_COUNT];
    // SAFETY: exact writable capacity for the scalar C oracle output.
    let count = unsafe { sys::sdk_layout(actual_layout.as_mut_ptr(), actual_layout.len()) };
    if count != actual_layout.len() || actual_layout != expected_layout {
        context.diagnostic(b"qualification-layout-count", count as u64);
        return false;
    }

    // SAFETY: scalar arguments match the independent native oracle signature.
    let scalar = unsafe {
        sys::sdk_scalar(
            -7,
            0xfedc_ba98,
            0x1234_5678_9abc_def0,
            0x8765_4321_0,
            0x1020_3040_5,
        )
    };
    let scalar_expected = ((-7i32 as u32 as u64) << 32)
        ^ 0xfedc_ba98
        ^ 0x1234_5678_9abc_def0
        ^ 0x8765_4321_0
        ^ 0x1020_3040_5;
    if scalar != scalar_expected {
        context.diagnostic(b"qualification-scalar-actual", scalar);
        return false;
    }

    for round in 0..10u64 {
        let input = 0x1020_3040_5060_7080 ^ round;
        let mut callback = |received| {
            if received == input {
                CALLBACK_SENTINEL
            } else {
                0
            }
        };
        match aros::call(context, &mut callback, input) {
            Ok(CALLBACK_SENTINEL) => {}
            Ok(actual) => {
                context.diagnostic(b"qualification-callback-actual", actual);
                return false;
            }
            Err(error) => {
                report_error(context, error);
                return false;
            }
        }
    }
    true
}

unsafe fn check_or_fill_pattern(
    pointer: *mut u8,
    length: usize,
    slot: usize,
    stamp: usize,
    fill: bool,
) -> bool {
    for index in 0..length {
        let expected = (index ^ slot ^ stamp) as u8;
        if fill {
            // SAFETY: caller provides a live block of at least length bytes.
            unsafe { pointer.add(index).write(expected) };
        } else {
            // SAFETY: caller provides a live block of at least length bytes.
            if unsafe { pointer.add(index).read() } != expected {
                return false;
            }
        }
    }
    true
}

fn allocation_aligned(pointer: *const u8, alignment: usize) -> bool {
    !pointer.is_null() && (pointer as usize) % alignment == 0
}

fn allocation_limits(context: &Context) -> bool {
    let baseline = context.statistics();
    let sizes = [1usize, 7, 64, 4096];
    let mut alignment = sys::MIN_ALLOCATION_ALIGNMENT;
    let mut combinations = 0usize;
    while alignment <= sys::MAX_ALLOCATION_ALIGNMENT {
        for size in sizes {
            // SAFETY: accepted layouts are released with their original size
            // and alignment after checking the returned pointer and pattern.
            let pointer = unsafe { sys::sdk_alloc(size, alignment).cast::<u8>() };
            if !allocation_aligned(pointer, alignment) {
                if !pointer.is_null() {
                    unsafe { sys::sdk_dealloc(pointer.cast(), size, alignment) };
                }
                return false;
            }
            // An isolated pointer copy must fail the same checker before any
            // dereference; the real allocation remains unchanged and owned.
            if alignment > 1 && allocation_aligned(pointer.wrapping_add(1), alignment) {
                unsafe { sys::sdk_dealloc(pointer.cast(), size, alignment) };
                return false;
            }
            if !unsafe { check_or_fill_pattern(pointer, size, 0, combinations, true) }
                || !unsafe { check_or_fill_pattern(pointer, size, 0, combinations, false) }
            {
                unsafe { sys::sdk_dealloc(pointer.cast(), size, alignment) };
                return false;
            }
            unsafe { sys::sdk_dealloc(pointer.cast(), size, alignment) };
            combinations += 1;
        }
        alignment <<= 1;
    }
    if combinations != 52 {
        return false;
    }

    for alignment in [1usize, 4096] {
        // SAFETY: the reference-sized payload is released with its original
        // allocation parameters after checking every byte.
        let pointer = unsafe { sys::sdk_alloc(MAX_IO_SIZE, alignment).cast::<u8>() };
        if !allocation_aligned(pointer, alignment) {
            if !pointer.is_null() {
                unsafe { sys::sdk_dealloc(pointer.cast(), MAX_IO_SIZE, alignment) };
            }
            return false;
        }
        if !unsafe { check_or_fill_pattern(pointer, MAX_IO_SIZE, 3, alignment, true) }
            || !unsafe { check_or_fill_pattern(pointer, MAX_IO_SIZE, 3, alignment, false) }
        {
            unsafe { sys::sdk_dealloc(pointer.cast(), MAX_IO_SIZE, alignment) };
            return false;
        }
        unsafe { sys::sdk_dealloc(pointer.cast(), MAX_IO_SIZE, alignment) };
    }

    // The native raw API explicitly supports zero-size requests. GlobalAlloc's
    // safety contract requires a nonzero Layout; ZST Rust values are tested
    // separately without invoking GlobalAlloc for a zero-size request.
    let zero = unsafe { sys::sdk_alloc(0, 16).cast::<u8>() };
    if !allocation_aligned(zero, 16) {
        if !zero.is_null() {
            unsafe { sys::sdk_dealloc(zero.cast(), 0, 16) };
        }
        return false;
    }
    unsafe { sys::sdk_dealloc(zero.cast(), 0, 16) };
    let allocator = aros::ExecAllocator;

    let layout = match Layout::from_size_align(64, 64) {
        Ok(layout) => layout,
        Err(_) => return false,
    };
    // SAFETY: matching layouts are used for every allocation release.
    let mut pointer = unsafe { GlobalAlloc::alloc_zeroed(&allocator, layout) };
    if pointer.is_null() || (pointer as usize) % 64 != 0 {
        if !pointer.is_null() {
            unsafe { GlobalAlloc::dealloc(&allocator, pointer, layout) };
        }
        return false;
    }
    for index in 0..64 {
        if unsafe { pointer.add(index).read() } != 0 {
            unsafe { GlobalAlloc::dealloc(&allocator, pointer, layout) };
            return false;
        }
        unsafe { pointer.add(index).write(index as u8) };
    }
    let grown = match Layout::from_size_align(4096, 64) {
        Ok(layout) => layout,
        Err(_) => {
            unsafe { GlobalAlloc::dealloc(&allocator, pointer, layout) };
            return false;
        }
    };
    let grown_pointer = unsafe { GlobalAlloc::realloc(&allocator, pointer, layout, 4096) };
    if grown_pointer.is_null() {
        unsafe { GlobalAlloc::dealloc(&allocator, pointer, layout) };
        return false;
    }
    pointer = grown_pointer;
    if (pointer as usize) % 64 != 0 {
        unsafe { GlobalAlloc::dealloc(&allocator, pointer, grown) };
        return false;
    }
    for index in 0..64 {
        if unsafe { pointer.add(index).read() } != index as u8 {
            unsafe { GlobalAlloc::dealloc(&allocator, pointer, grown) };
            return false;
        }
    }
    let shrunk = match Layout::from_size_align(16, 64) {
        Ok(layout) => layout,
        Err(_) => {
            unsafe { GlobalAlloc::dealloc(&allocator, pointer, grown) };
            return false;
        }
    };
    let shrunk_pointer = unsafe { GlobalAlloc::realloc(&allocator, pointer, grown, 16) };
    if shrunk_pointer.is_null() {
        unsafe { GlobalAlloc::dealloc(&allocator, pointer, grown) };
        return false;
    }
    pointer = shrunk_pointer;
    if (pointer as usize) % 64 != 0 {
        unsafe { GlobalAlloc::dealloc(&allocator, pointer, shrunk) };
        return false;
    }
    for index in 0..16 {
        if unsafe { pointer.add(index).read() } != index as u8 {
            unsafe { GlobalAlloc::dealloc(&allocator, pointer, shrunk) };
            return false;
        }
    }
    unsafe { GlobalAlloc::dealloc(&allocator, pointer, shrunk) };

    let zst = Vec::<()>::with_capacity(4096);
    if zst.capacity() != usize::MAX {
        return false;
    }
    drop(zst);

    // Unsupported layouts must fail without a native allocation or lost block.
    let before_refusals = context.statistics();
    let invalid_alignment = unsafe { sys::sdk_alloc(64, sys::MAX_ALLOCATION_ALIGNMENT * 2) };
    let oversized = unsafe { sys::sdk_alloc(isize::MAX as usize + 1, 8) };
    let overflow = unsafe { sys::sdk_alloc(usize::MAX, 4096) };
    let layout_overflow = Layout::from_size_align(usize::MAX, 4096).is_err();
    if !invalid_alignment.is_null()
        || !oversized.is_null()
        || !overflow.is_null()
        || !layout_overflow
    {
        if !invalid_alignment.is_null() {
            unsafe { sys::sdk_dealloc(invalid_alignment, 64, sys::MAX_ALLOCATION_ALIGNMENT * 2) };
        }
        if !oversized.is_null() {
            unsafe { sys::sdk_dealloc(oversized, isize::MAX as usize + 1, 8) };
        }
        if !overflow.is_null() {
            unsafe { sys::sdk_dealloc(overflow, usize::MAX, 4096) };
        }
        return false;
    }

    let after = context.statistics();
    same_resources(baseline, after)
        && same_resources(before_refusals, after)
        && after.refusals >= before_refusals.refusals + 3
}

#[derive(Clone, Copy)]
struct AllocationSlot {
    pointer: *mut u8,
    size: usize,
    alignment: usize,
    stamp: usize,
}

// Separate from the inherited small-reference matrix: these simultaneous
// payloads exceed the former per-allocation, heap and whole-owner quotas.
fn large_allocations(context: &Context) -> bool {
    let baseline = context.statistics();
    let sizes = [32 * 1024 * 1024 + 17, 17 * 1024 * 1024 + 31];
    let mut pointers = [ptr::null_mut::<u8>(); 2];
    let mut passed = true;
    for (slot, size) in sizes.into_iter().enumerate() {
        // SAFETY: each successful raw allocation is released below with its
        // original parameters, including on a later refusal.
        pointers[slot] = unsafe { sys::sdk_alloc(size, 4096).cast::<u8>() };
        if !allocation_aligned(pointers[slot], 4096) {
            passed = false;
            break;
        }
        // Touch every page and the final payload byte; neither a small backing
        // allocation nor overlapping live blocks can satisfy this probe.
        for index in (0..size).step_by(4096).chain(core::iter::once(size - 1)) {
            unsafe {
                pointers[slot]
                    .add(index)
                    .write((slot * 71 + index % 251) as u8)
            };
        }
    }
    if passed {
        for (slot, size) in sizes.into_iter().enumerate() {
            for index in (0..size).step_by(4096).chain(core::iter::once(size - 1)) {
                if unsafe { pointers[slot].add(index).read() } != (slot * 71 + index % 251) as u8 {
                    passed = false;
                }
            }
        }
        passed &= context.statistics().blocks == baseline.blocks + 2;
    }
    for (slot, size) in sizes.into_iter().enumerate() {
        if !pointers[slot].is_null() {
            unsafe { sys::sdk_dealloc(pointers[slot].cast(), size, 4096) };
        }
    }
    passed && same_resources(baseline, context.statistics())
}

fn next_m0_state(state: &mut u32) -> u32 {
    *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    *state
}

fn allocator_workload(context: &Context) -> bool {
    let baseline = context.statistics();
    let mut slots = [AllocationSlot {
        pointer: ptr::null_mut(),
        size: 0,
        alignment: 0,
        stamp: 0,
    }; 32];
    let mut state = M0_SEED;
    let mut counts = [0usize; 4];
    let mut seen_slots = [false; 32];
    let mut seen_alignments = [false; 10];

    for operation in 0..1000usize {
        let kind = (next_m0_state(&mut state) >> 16) % 4;
        let slot = ((next_m0_state(&mut state) >> 16) % 32) as usize;
        let size = 1 + (next_m0_state(&mut state) % 65_536) as usize;
        let alignment = 1usize << (3 + ((next_m0_state(&mut state) >> 16) % 10));
        counts[kind as usize] += 1;
        seen_slots[slot] = true;
        seen_alignments[alignment.trailing_zeros() as usize - 3] = true;

        let mut old = slots[slot];
        if !old.pointer.is_null()
            && !unsafe { check_or_fill_pattern(old.pointer, old.size, slot, old.stamp, false) }
        {
            return false;
        }

        if (kind == 0 || kind == 3) && !old.pointer.is_null() {
            unsafe { sys::sdk_dealloc(old.pointer.cast(), old.size, old.alignment) };
            old.pointer = ptr::null_mut();
        }

        if kind == 1 {
            if !old.pointer.is_null() {
                unsafe { sys::sdk_dealloc(old.pointer.cast(), old.size, old.alignment) };
            }
            slots[slot] = AllocationSlot {
                pointer: ptr::null_mut(),
                size: 0,
                alignment: 0,
                stamp: 0,
            };
            continue;
        }

        let selected_alignment = if kind == 2 && !old.pointer.is_null() {
            old.alignment
        } else {
            alignment
        };
        let fresh = unsafe { sys::sdk_alloc(size, selected_alignment).cast::<u8>() };
        if fresh.is_null() || (fresh as usize) % selected_alignment != 0 {
            if !fresh.is_null() {
                unsafe { sys::sdk_dealloc(fresh.cast(), size, selected_alignment) };
            }
            return false;
        }

        if kind == 2 && !old.pointer.is_null() {
            let preserved = core::cmp::min(size, old.size);
            unsafe { ptr::copy_nonoverlapping(old.pointer, fresh, preserved) };
            if !unsafe { check_or_fill_pattern(fresh, preserved, slot, old.stamp, false) } {
                unsafe { sys::sdk_dealloc(fresh.cast(), size, selected_alignment) };
                return false;
            }
        }

        if kind == 3 {
            unsafe { ptr::write_bytes(fresh, 0, size) };
            for index in 0..size {
                if unsafe { fresh.add(index).read() } != 0 {
                    unsafe { sys::sdk_dealloc(fresh.cast(), size, selected_alignment) };
                    return false;
                }
            }
        }

        if !old.pointer.is_null() {
            unsafe { sys::sdk_dealloc(old.pointer.cast(), old.size, old.alignment) };
        }
        if !unsafe { check_or_fill_pattern(fresh, size, slot, operation, true) } {
            unsafe { sys::sdk_dealloc(fresh.cast(), size, selected_alignment) };
            return false;
        }
        slots[slot] = AllocationSlot {
            pointer: fresh,
            size,
            alignment: selected_alignment,
            stamp: operation,
        };
    }

    if counts != [247, 249, 233, 271] || seen_slots.iter().any(|seen| !seen) {
        return false;
    }
    if seen_alignments.iter().any(|seen| !seen) {
        return false;
    }

    for (slot, entry) in slots.iter().enumerate() {
        if !entry.pointer.is_null() {
            if !unsafe {
                check_or_fill_pattern(entry.pointer, entry.size, slot, entry.stamp, false)
            } {
                return false;
            }
            unsafe { sys::sdk_dealloc(entry.pointer.cast(), entry.size, entry.alignment) };
        }
    }

    for length in [0usize, 1, 7, 64, 4096] {
        let mut vector = Vec::new();
        let mut string = String::new();
        if vector.try_reserve_exact(length).is_err() || string.try_reserve_exact(length).is_err() {
            return false;
        }
        for index in 0..length {
            vector.push(index as u8);
            string.push('x');
        }
        if vector.len() != length || string.len() != length {
            return false;
        }
        vector.resize(length * 2, 0);
        vector.truncate(length / 2);
        vector.shrink_to_fit();
        string.truncate(length / 2);
        string.shrink_to_fit();
    }

    let mut map = BTreeMap::new();
    for key in 0..128usize {
        map.insert(key, key * 7);
    }
    for key in (0..128usize).step_by(2) {
        if map.remove(&key) != Some(key * 7) {
            return false;
        }
    }
    for key in (1..128usize).step_by(2) {
        if map.remove(&key) != Some(key * 7) {
            return false;
        }
    }
    if !map.is_empty() {
        return false;
    }
    drop(map);

    let after = context.statistics();
    same_resources(baseline, after) && after.blocks == 0 && after.backing_charge == 0
}

fn round_trip_file(
    context: &Context,
    path_bytes: &[u8],
    length: usize,
    source: &[u8],
    destination: &mut [u8],
) -> bool {
    let Some(path) = byte_path(path_bytes) else {
        return false;
    };
    let mut file = match File::open(context, &path, FileMode::CreateTruncate) {
        Ok(file) => file,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    if let Err(error) = file.write_all(&source[..length]) {
        report_error(context, error);
        return false;
    }
    if let Err(error) = file.close() {
        report_error(context, error);
        return false;
    }

    let mut file = match File::open(context, &path, FileMode::ReadExisting) {
        Ok(file) => file,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    if let Err(error) = file.read_exact(&mut destination[..length]) {
        report_error(context, error);
        return false;
    }
    if source[..length] != destination[..length] {
        return false;
    }
    let mut extra = [0u8; 1];
    match file.read(&mut extra) {
        Ok(0) => {}
        Ok(count) => {
            context.diagnostic(b"qualification-file-trailing-bytes", count as u64);
            return false;
        }
        Err(error) => {
            report_error(context, error);
            return false;
        }
    }
    match file.close() {
        Ok(()) => true,
        Err(error) => {
            report_error(context, error);
            false
        }
    }
}

fn file_and_path_cases(context: &Context) -> bool {
    let baseline = context.statistics();
    let Some(source) = make_sequence(MAX_IO_SIZE) else {
        return false;
    };
    let Some(mut destination) = make_sequence(MAX_IO_SIZE) else {
        return false;
    };

    let sentinel_bytes = [0x41, 0x52, 0x4f, 0x53];
    let Some(sentinel_path) = byte_path(b"RAM:ami-rust-m1/unrelated.bin") else {
        return false;
    };
    let mut sentinel = match File::open(context, &sentinel_path, FileMode::CreateTruncate) {
        Ok(file) => file,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    if let Err(error) = sentinel.write_all(&sentinel_bytes) {
        report_error(context, error);
        return false;
    }
    if let Err(error) = sentinel.close() {
        report_error(context, error);
        return false;
    }

    for repetition in 0..10usize {
        for (path, length) in FILE_CASES {
            if !round_trip_file(context, path, length, &source, &mut destination) {
                context.diagnostic(b"qualification-file-case", repetition as u64);
                return false;
            }
        }
    }

    let nul_path = BytePath::new(b"RAM:ami-rust-m1/bad\0path");
    if !expect_error(context, nul_path, ErrorKind::Input) {
        return false;
    }
    if !matches!(BytePath::new(&[0xff]), Ok(path) if path.len() == 1) {
        return false;
    }
    let too_long = [b'x'; 128];
    if !expect_error(context, BytePath::new(&too_long), ErrorKind::Limit) {
        return false;
    }

    let missing_path = match byte_path(b"RAM:ami-rust-m1/absent-input.bin") {
        Some(path) => path,
        None => return false,
    };
    if !expect_error(
        context,
        File::open(context, &missing_path, FileMode::ReadExisting),
        ErrorKind::Native,
    ) {
        return false;
    }

    let empty_path = match byte_path(FILE_CASES[0].0) {
        Some(path) => path,
        None => return false,
    };
    let mut empty_file = match File::open(context, &empty_path, FileMode::ReadExisting) {
        Ok(file) => file,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    let mut one_byte = [0u8; 1];
    if !expect_error(
        context,
        empty_file.read_exact(&mut one_byte),
        ErrorKind::Eof,
    ) {
        return false;
    }
    if let Err(error) = empty_file.close() {
        report_error(context, error);
        return false;
    }

    // Explicit close consumes the wrapper; a normal drop closes exactly once.
    let explicit = match File::open(context, &empty_path, FileMode::ReadExisting) {
        Ok(file) => file,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    if let Err(error) = explicit.close() {
        report_error(context, error);
        return false;
    }
    drop(
        match File::open(context, &empty_path, FileMode::ReadExisting) {
            Ok(file) => file,
            Err(error) => {
                report_error(context, error);
                return false;
            }
        },
    );

    // Test a stale native token only inside this raw qualification fixture; no
    // token is adopted into or exposed by the safe SDK.
    let raw_name = b"RAM:ami-rust-m1/stale-token.bin\0";
    let mut raw_error = SdkError::default();
    let raw_token = unsafe {
        sys::sdk_file_open(
            context.key(),
            raw_name.as_ptr(),
            FileMode::CreateTruncate as i32,
            &mut raw_error,
        )
    };
    if raw_token == 0
        || unsafe { sys::sdk_file_close(context.key(), raw_token, &mut raw_error) } != 0
    {
        context.diagnostic(
            b"qualification-stale-token-open-close",
            raw_error.native as u64,
        );
        return false;
    }

    raw_error = SdkError::default();
    let replacement_token = unsafe {
        sys::sdk_file_open(
            context.key(),
            raw_name.as_ptr(),
            FileMode::CreateTruncate as i32,
            &mut raw_error,
        )
    };
    if replacement_token == 0 || replacement_token == raw_token {
        if replacement_token != 0 {
            unsafe { sys::sdk_file_close(context.key(), replacement_token, &mut raw_error) };
        }
        context.diagnostic(
            b"qualification-stale-token-reuse-open",
            raw_error.native as u64,
        );
        return false;
    }

    raw_error = SdkError::default();
    if unsafe { sys::sdk_file_close(context.key(), raw_token, &mut raw_error) } != -1
        || raw_error.kind != sys::ERROR_KIND_STATE
    {
        unsafe { sys::sdk_file_close(context.key(), replacement_token, &mut raw_error) };
        context.diagnostic(b"qualification-stale-token-error", raw_error.native as u64);
        return false;
    }
    let stale = Error {
        kind: ErrorKind::State,
        native: raw_error.native,
        operation: aros::Operation::FileClose,
    };
    report_error(context, stale);
    if context.statistics().files != baseline.files + 1 {
        unsafe { sys::sdk_file_close(context.key(), replacement_token, &mut raw_error) };
        return false;
    }
    raw_error = SdkError::default();
    if unsafe { sys::sdk_file_close(context.key(), replacement_token, &mut raw_error) } != 0
        || context.statistics().files != baseline.files
    {
        context.diagnostic(
            b"qualification-stale-token-replacement-close",
            raw_error.native as u64,
        );
        return false;
    }

    // The 0.1 registry held 16 files; 40 prove the registry grows on demand.
    set_slot_limit(40);
    let mut files: [Option<File<'_>>; 40] = core::array::from_fn(|_| None);
    for file in &mut files {
        *file = match File::open(context, &empty_path, FileMode::ReadExisting) {
            Ok(file) => Some(file),
            Err(error) => {
                report_error(context, error);
                return false;
            }
        };
    }
    if !expect_error(
        context,
        File::open(context, &empty_path, FileMode::ReadExisting),
        ErrorKind::Limit,
    ) {
        set_slot_limit(0);
        return false;
    }
    set_slot_limit(0);
    drop(files);
    if context.statistics().files != baseline.files {
        return false;
    }

    let mut sentinel = match File::open(context, &sentinel_path, FileMode::ReadExisting) {
        Ok(file) => file,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    let mut observed_sentinel = [0u8; 4];
    if let Err(error) = sentinel.read_exact(&mut observed_sentinel) {
        report_error(context, error);
        return false;
    }
    let mut extra = [0u8; 1];
    if observed_sentinel != sentinel_bytes {
        return false;
    }
    match sentinel.read(&mut extra) {
        Ok(0) => {}
        Ok(count) => {
            context.diagnostic(b"qualification-sentinel-length", count as u64);
            return false;
        }
        Err(error) => {
            report_error(context, error);
            return false;
        }
    }
    if let Err(error) = sentinel.close() {
        report_error(context, error);
        return false;
    }

    drop(source);
    drop(destination);
    same_resources(baseline, context.statistics())
}

fn library_cases(context: &Context) -> bool {
    let baseline = context.statistics();
    let Some(name) = byte_path(b"dos.library") else {
        return false;
    };
    if !expect_error(
        context,
        Library::open(context, &name, u16::MAX),
        ErrorKind::Native,
    ) {
        return false;
    }

    // The 0.1 registry held 4 libraries; 24 prove the registry grows on demand.
    set_slot_limit(24);
    let mut libraries: [Option<Library<'_>>; 24] = core::array::from_fn(|_| None);
    for library in &mut libraries {
        *library = match Library::open(context, &name, 0) {
            Ok(library) => Some(library),
            Err(error) => {
                report_error(context, error);
                return false;
            }
        };
    }
    if !expect_error(context, Library::open(context, &name, 0), ErrorKind::Limit) {
        set_slot_limit(0);
        return false;
    }
    set_slot_limit(0);
    let Some(first) = libraries[0].take() else {
        return false;
    };
    if let Err(error) = first.close() {
        report_error(context, error);
        return false;
    }
    drop(libraries);
    same_resources(baseline, context.statistics())
}

/// Registries grow beyond the 0.1 limits, report `Limit` at their token-space
/// bound, return every slot when handles are dropped, and leave handles that
/// are forgotten to the native end-of-run cleanup (checked by the ledgers the
/// native bridge prints at exit).
fn registry_growth_cases(context: &Context) -> bool {
    let baseline = context.statistics();
    let Some(empty_path) = byte_path(b"RAM:ami-rust-m1/fixture-1.bin") else {
        return false;
    };

    // Messages: far beyond the 0.1 limit of 8, then the bound, then reuse.
    set_slot_limit(64);
    let mut messages: [Option<Message<'_>>; 64] = core::array::from_fn(|_| None);
    for (index, message) in messages.iter_mut().enumerate() {
        let bytes = [index as u8; 32];
        *message = match Message::new(context, &bytes) {
            Ok(message) => Some(message),
            Err(error) => {
                report_error(context, error);
                set_slot_limit(0);
                return false;
            }
        };
    }
    let exhausted = expect_error(context, Message::new(context, b"over"), ErrorKind::Limit);
    set_slot_limit(0);
    if !exhausted {
        return false;
    }
    // Releasing one record frees its slot for the next request.
    drop(messages[17].take());
    set_slot_limit(64);
    let reused = Message::new(context, b"reuse");
    set_slot_limit(0);
    match reused {
        Ok(message) => drop(message),
        Err(error) => {
            report_error(context, error);
            return false;
        }
    }
    drop(messages);
    if !same_resources(baseline, context.statistics()) {
        return false;
    }

    // Ports: more than the 0.1 limit of 2, bounded, and every signal returned.
    set_slot_limit(6);
    let mut ports: [Option<Port<'_>>; 6] = core::array::from_fn(|_| None);
    for port in &mut ports {
        *port = match Port::new(context) {
            Ok(port) => Some(port),
            Err(error) => {
                report_error(context, error);
                set_slot_limit(0);
                return false;
            }
        };
    }
    let exhausted = expect_error(context, Port::new(context), ErrorKind::Limit);
    set_slot_limit(0);
    if !exhausted {
        return false;
    }
    drop(ports);
    if !same_resources(baseline, context.statistics()) {
        return false;
    }

    // Signals are limited by Exec, not by the registry: more than the 0.1
    // limit of 4 must succeed, and exhaustion is a native refusal.
    let mut signals: [Option<Signal<'_>>; 32] = core::array::from_fn(|_| None);
    let mut count = 0usize;
    let mut refused = false;
    for slot in &mut signals {
        match Signal::new(context) {
            Ok(signal) => {
                *slot = Some(signal);
                count += 1;
            }
            Err(error) if error.kind == ErrorKind::Native => {
                refused = true;
                break;
            }
            Err(error) => {
                report_error(context, error);
                return false;
            }
        }
    }
    context.diagnostic(b"qualification-signal-count", count as u64);
    drop(signals);
    if count <= 4 || !refused || !same_resources(baseline, context.statistics()) {
        return false;
    }

    // Handles that are forgotten stay registered until the native cleanup.
    set_slot_limit(0);
    let mut forgotten = 0u64;
    for _ in 0..20 {
        match File::open(context, &empty_path, FileMode::ReadExisting) {
            Ok(file) => {
                core::mem::forget(file);
                forgotten += 1;
            }
            Err(error) => {
                report_error(context, error);
                return false;
            }
        }
    }
    for _ in 0..50 {
        match Message::new(context, b"forgotten") {
            Ok(message) => {
                core::mem::forget(message);
                forgotten += 1;
            }
            Err(error) => {
                report_error(context, error);
                return false;
            }
        }
    }
    for _ in 0..4 {
        match Port::new(context) {
            Ok(port) => {
                core::mem::forget(port);
                forgotten += 1;
            }
            Err(error) => {
                report_error(context, error);
                return false;
            }
        }
    }
    let live = context.statistics();
    context.diagnostic(b"qualification-forgotten-handles", forgotten);
    live.files == baseline.files + 20
        && live.messages == baseline.messages + 50
        && live.ports == baseline.ports + 4
}

const UNIT_VBLANK: u32 = 1;
const TR_ADDREQUEST: u16 = 9;
const TR_GETSYSTIME: u16 = 10;
const IOERR_ABORTED: i8 = -2;

fn timer_device<'a>(context: &'a Context) -> Option<Device<'a>> {
    let name = byte_path(b"timer.device")?;
    match Device::open(context, &name, UNIT_VBLANK, 0) {
        Ok(device) => Some(device),
        Err(error) => {
            report_error(context, error);
            None
        }
    }
}

fn timer_request<'d, 'a>(
    device: &'d Device<'a>,
    seconds: u32,
    micros: u32,
) -> Option<Request<'d, 'a>> {
    let mut request = Request::new(device, RequestKind::Timer, 0).ok()?;
    request.prepare(TR_ADDREQUEST, 0, 0, 0).ok()?;
    request.set_time(seconds, micros).ok()?;
    Some(request)
}

/// Device open and close, synchronous and asynchronous requests, abort, drop
/// of a pending request, input and state refusals, registry growth and an
/// injected `OpenDevice` failure; every case ends at the baseline counters.
fn device_cases(context: &Context) -> bool {
    let baseline = context.statistics();

    // A missing device is a native failure that leaves nothing behind.
    let Some(missing) = byte_path(b"ami-rust-missing.device") else {
        return false;
    };
    if !expect_error(
        context,
        Device::open(context, &missing, 0, 0),
        ErrorKind::Native,
    ) || !same_resources(baseline, context.statistics())
    {
        return false;
    }
    // An injected OpenDevice failure behaves the same way.
    set_fault(FAULT_OPEN_DEVICE);
    let injected = timer_device(context);
    reset_fault();
    if injected.is_some() || !same_resources(baseline, context.statistics()) {
        return false;
    }

    let Some(device) = timer_device(context) else {
        return false;
    };
    if device.signal_mask() == 0 {
        return false;
    }

    // TR_GETSYSTIME: a synchronous request fills in the system time.
    let Some(mut clock) = Request::new(&device, RequestKind::Timer, 0).ok() else {
        return false;
    };
    if clock.prepare(TR_GETSYSTIME, 0, 0, 0).is_err() {
        return false;
    }
    match clock.do_io() {
        Ok(outcome) if outcome.is_ok() => {}
        _ => return false,
    }
    match clock.time() {
        Ok((seconds, micros)) if seconds != 0 && micros < 1_000_000 => {}
        _ => return false,
    }
    drop(clock);

    // Asynchronous 50 ms request: signalled through the device's reply port.
    let Some(mut sleeper) = timer_request(&device, 0, 50_000) else {
        return false;
    };
    if sleeper.send().is_err()
        || !expect_error(context, sleeper.send(), ErrorKind::State)
        || !expect_error(
            context,
            sleeper.prepare(TR_ADDREQUEST, 0, 0, 0),
            ErrorKind::State,
        )
        || !expect_error(context, sleeper.outcome(), ErrorKind::State)
        || wait_signals(context, device.signal_mask()).is_err()
        || sleeper.check() != Ok(true)
    {
        return false;
    }
    match sleeper.wait() {
        Ok(outcome) if outcome.is_ok() => {}
        _ => return false,
    }
    if !expect_error(context, sleeper.wait(), ErrorKind::State)
        || !expect_error(context, sleeper.check(), ErrorKind::State)
        || !expect_error(context, sleeper.abort(), ErrorKind::State)
    {
        return false;
    }
    drop(sleeper);

    // Abort: a ten second request is returned at once with IOERR_ABORTED.
    let Some(mut long) = timer_request(&device, 10, 0) else {
        return false;
    };
    if long.send().is_err() || long.abort().is_err() {
        return false;
    }
    match long.wait() {
        Ok(outcome) if outcome.device_error == IOERR_ABORTED => {}
        _ => return false,
    }
    drop(long);

    // Dropping a pending request aborts it and leaves no message queued.
    let Some(mut pending) = timer_request(&device, 10, 0) else {
        return false;
    };
    if pending.send().is_err() {
        return false;
    }
    drop(pending);

    // Refusals before any native work.
    if !expect_error(
        context,
        Request::new(&device, RequestKind::Timer, 1),
        ErrorKind::Input,
    ) || !expect_error(
        context,
        Request::new(
            &device,
            RequestKind::Standard,
            sys::MAX_REQUEST_DATA_BYTES + 1,
        ),
        ErrorKind::Input,
    ) {
        return false;
    }
    let Some(mut timer) = Request::new(&device, RequestKind::Timer, 0).ok() else {
        return false;
    };
    if !expect_error(context, timer.set_time(0, 1_000_000), ErrorKind::Input)
        || !expect_error(
            context,
            timer.prepare(TR_ADDREQUEST, 0, 1, 0),
            ErrorKind::Input,
        )
        || !expect_error(context, timer.write_data(b"x"), ErrorKind::State)
        || !expect_error(context, timer.wait(), ErrorKind::State)
    {
        return false;
    }
    drop(timer);
    let Some(mut standard) = Request::new(&device, RequestKind::Standard, 8).ok() else {
        return false;
    };
    let mut copy = [0u8; 8];
    if standard.write_data(&[1u8; 9]).is_ok()
        || !expect_error(context, standard.write_data(&[1u8; 9]), ErrorKind::Input)
        || standard.write_data(b"payload!").is_err()
        || standard.prepare(0, 0, 9, 0).is_ok()
        || standard.read_data(&mut copy) != Ok(0)
        || standard.set_time(0, 1).is_ok()
    {
        return false;
    }
    drop(standard);

    // The device cannot close while a request exists: the borrow forbids it
    // here, and the native registry refuses it for a raw token as well.
    // Registry growth: requests beyond any small fixed table, then the bound.
    set_slot_limit(40);
    let mut requests: [Option<Request<'_, '_>>; 40] = core::array::from_fn(|_| None);
    for request in &mut requests {
        *request = Request::new(&device, RequestKind::Timer, 0).ok();
        if request.is_none() {
            set_slot_limit(0);
            return false;
        }
    }
    let exhausted = expect_error(
        context,
        Request::new(&device, RequestKind::Timer, 0),
        ErrorKind::Limit,
    );
    set_slot_limit(0);
    if !exhausted {
        return false;
    }
    drop(requests);

    if device.close().is_err() {
        return false;
    }
    same_resources(baseline, context.statistics())
}

/// Leaves a device with a pending request and an idle one forgotten, so the
/// native end-of-run cleanup must abort, reclaim and release them. The ledgers
/// printed at exit must all be zero.
fn device_forgotten_cases(context: &Context) -> bool {
    let baseline = context.statistics();
    let Some(device) = timer_device(context) else {
        return false;
    };
    let Some(mut pending) = timer_request(&device, 10, 0) else {
        return false;
    };
    let Some(idle) = Request::new(&device, RequestKind::Standard, 64).ok() else {
        return false;
    };
    if pending.send().is_err() {
        return false;
    }
    let live = context.statistics();
    context.diagnostic(b"qualification-forgotten-requests", live.requests as u64);
    let ok = live.devices == baseline.devices + 1 && live.requests == baseline.requests + 2;
    mem::forget(pending);
    mem::forget(idle);
    mem::forget(device);
    ok
}

fn signal_port_message_cases(context: &Context) -> bool {
    let baseline = context.statistics();
    let port_a = match Port::new(context) {
        Ok(port) => port,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    let port_b = match Port::new(context) {
        Ok(port) => port,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };

    let signal_a = match Signal::new(context) {
        Ok(signal) => signal,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    let signal_b = match Signal::new(context) {
        Ok(signal) => signal,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    for _ in 0..10 {
        if let Err(error) = signal_a.post().and_then(|()| signal_a.wait()) {
            report_error(context, error);
            return false;
        }
    }
    drop(signal_a);
    drop(signal_b);

    let mut messages: [Option<Message<'_>>; 8] = core::array::from_fn(|_| None);
    for (index, message) in messages.iter_mut().enumerate() {
        let bytes = [index as u8; 256];
        *message = match Message::new(context, &bytes) {
            Ok(message) => Some(message),
            Err(error) => {
                report_error(context, error);
                return false;
            }
        };
    }
    drop(messages);

    let mut payload = [0u8; 256];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = (index.wrapping_mul(17) ^ 0xa5) as u8;
    }
    let mut message = match Message::new(context, &payload) {
        Ok(message) => message,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };

    if !expect_error(context, message.reply(), ErrorKind::State) {
        return false;
    }
    if port_a.receive(&mut message) != Ok(false) {
        return false;
    }

    let mut first = match Message::new(context, b"first queued message") {
        Ok(message) => message,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    let mut second = match Message::new(context, b"second queued message") {
        Ok(message) => message,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    if let Err(error) = port_a.send(&mut first, &port_a) {
        report_error(context, error);
        return false;
    }
    if let Err(error) = port_a.send(&mut second, &port_a) {
        report_error(context, error);
        return false;
    }
    let mut copied = [0u8; 256];
    if !expect_error(context, port_a.receive(&mut second), ErrorKind::State)
        || !expect_error(context, first.copy_to(&mut copied), ErrorKind::State)
        || !expect_error(context, port_a.send(&mut first, &port_a), ErrorKind::State)
        || port_a.receive(&mut first) != Ok(true)
    {
        return false;
    }
    if let Err(error) = first.reply() {
        report_error(context, error);
        return false;
    }
    if !expect_error(context, port_a.receive(&mut first), ErrorKind::State)
        || port_a.receive(&mut second) != Ok(true)
    {
        return false;
    }
    if let Err(error) = second.reply() {
        report_error(context, error);
        return false;
    }
    if port_a.receive(&mut first) != Ok(true) || port_a.receive(&mut second) != Ok(true) {
        return false;
    }
    drop(first);
    drop(second);

    for _ in 0..10 {
        if let Err(error) = port_b.send(&mut message, &port_b) {
            report_error(context, error);
            return false;
        }
        if port_b.receive(&mut message) != Ok(true) {
            return false;
        }
        let mut copied = [0u8; 256];
        match message.copy_to(&mut copied) {
            Ok(256) if copied == payload => {}
            Ok(count) => {
                context.diagnostic(b"qualification-message-copy-count", count as u64);
                return false;
            }
            Err(error) => {
                report_error(context, error);
                return false;
            }
        }
        if let Err(error) = message.reply() {
            report_error(context, error);
            return false;
        }
        if port_b.receive(&mut message) != Ok(true) {
            return false;
        }
    }

    // Port destruction detaches the queued message and resets its registry
    // state. The safe wrapper deliberately has no local state mirror.
    if let Err(error) = port_a.send(&mut message, &port_b) {
        report_error(context, error);
        return false;
    }
    drop(port_a);
    if !expect_error(context, message.reply(), ErrorKind::State) {
        return false;
    }
    let mut copied = [0u8; 256];
    if message.copy_to(&mut copied) != Ok(256) || copied != payload {
        return false;
    }

    // A delivered message also becomes locally owned if its reply route is
    // destroyed. The native registry clears that route and resets its state.
    let port_a = match Port::new(context) {
        Ok(port) => port,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    let mut routed = match Message::new(context, &payload) {
        Ok(message) => message,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    if let Err(error) = port_b.send(&mut routed, &port_a) {
        report_error(context, error);
        return false;
    }
    if port_b.receive(&mut routed) != Ok(true) {
        return false;
    }
    drop(port_a);
    if !expect_error(context, routed.reply(), ErrorKind::State)
        || routed.copy_to(&mut copied) != Ok(256)
        || copied != payload
    {
        return false;
    }
    drop(routed);

    if let Err(error) = port_b.send(&mut message, &port_b) {
        report_error(context, error);
        return false;
    }
    if port_b.receive(&mut message) != Ok(true)
        || message.reply().is_err()
        || port_b.receive(&mut message) != Ok(true)
    {
        return false;
    }

    drop(message);
    drop(port_b);
    same_resources(baseline, context.statistics())
}

fn nested_callback_refused(context: &Context, value: u64) -> bool {
    let mut invoked = false;
    let mut nested = |input| {
        invoked = true;
        input
    };
    let result = aros::call(context, &mut nested, value);
    drop(nested);
    matches!(result, Err(error) if error.kind == ErrorKind::State) && !invoked
}

unsafe extern "C" fn count_raw_callback(user_data: *mut c_void, value: u64) -> u64 {
    // SAFETY: the owner test passes a live pointer to a stack counter; a correct
    // native owner check refuses before invoking this callback.
    let counter = unsafe { &mut *user_data.cast::<usize>() };
    *counter += 1;
    value
}

fn callback_result_has_sentinel(result: Result<u64, Error>) -> bool {
    matches!(result, Ok(value) if value == CALLBACK_SENTINEL)
}

fn callback_cases(context: &Context) -> bool {
    for round in 0..10u64 {
        let mut nested_refused = false;
        let mut callback = |input| {
            nested_refused = nested_callback_refused(context, input);
            CALLBACK_SENTINEL
        };
        let result = aros::call(context, &mut callback, round);
        if !callback_result_has_sentinel(result) || !nested_refused {
            return false;
        }
    }

    let wrong_sentinel = CALLBACK_SENTINEL ^ 1;
    let mut wrong_callback = |_| wrong_sentinel;
    let wrong_result = aros::call(context, &mut wrong_callback, 0x1234);
    if callback_result_has_sentinel(wrong_result)
        || !matches!(wrong_result, Ok(value) if value == wrong_sentinel)
    {
        return false;
    }

    let mut count = 0usize;
    let mut output = 0u64;
    let mut native_error = SdkError::default();
    // SAFETY: the forged owner key must be rejected before the callback or
    // user_data is dereferenced by the native bridge.
    let rejected = unsafe {
        sys::sdk_callback(
            context.key().wrapping_add(1),
            count_raw_callback,
            (&mut count as *mut usize).cast(),
            0x1234,
            &mut output,
            &mut native_error,
        )
    };
    if rejected != -1
        || native_error.kind != sys::ERROR_KIND_OWNER
        || count != 0
        || !expected_raw_error(
            context,
            native_error,
            ErrorKind::Owner,
            aros::Operation::Callback,
        )
    {
        context.diagnostic(
            b"qualification-callback-owner-refusal",
            native_error.native as u64,
        );
        return false;
    }

    let baseline = context.statistics();
    let mut setup_error = SdkError::default();
    let signal = unsafe { sys::sdk_signal_new(context.key(), &mut setup_error) };
    if signal == 0 || setup_error.kind != 0 {
        return false;
    }
    setup_error = SdkError::default();
    let port = unsafe { sys::sdk_port_new(context.key(), &mut setup_error) };
    if port == 0 || setup_error.kind != 0 {
        return false;
    }
    let message_bytes = b"owner-guard-message";
    setup_error = SdkError::default();
    let message = unsafe {
        sys::sdk_message_new(
            context.key(),
            message_bytes.as_ptr(),
            message_bytes.len(),
            &mut setup_error,
        )
    };
    if message == 0 || setup_error.kind != 0 {
        return false;
    }
    let live = context.statistics();
    if live.signals != baseline.signals + 2
        || live.ports != baseline.ports + 1
        || live.messages != baseline.messages + 1
    {
        return false;
    }

    let wrong_key = context.key().wrapping_add(1);
    let mut owner_error = SdkError::default();
    let refused = unsafe { sys::sdk_signal_post(wrong_key, signal, &mut owner_error) };
    if !expect_raw_owner_refusal(context, refused, owner_error, aros::Operation::SignalPost) {
        return false;
    }
    owner_error = SdkError::default();
    let refused = unsafe { sys::sdk_signal_drop(wrong_key, signal, &mut owner_error) };
    if !expect_raw_owner_refusal(context, refused, owner_error, aros::Operation::SignalDrop) {
        return false;
    }

    owner_error = SdkError::default();
    let refused = unsafe { sys::sdk_port_drop(wrong_key, port, &mut owner_error) };
    if !expect_raw_owner_refusal(context, refused, owner_error, aros::Operation::PortDrop) {
        return false;
    }
    owner_error = SdkError::default();
    let refused = unsafe { sys::sdk_port_put(wrong_key, port, message, port, &mut owner_error) };
    if !expect_raw_owner_refusal(context, refused, owner_error, aros::Operation::PortSend) {
        return false;
    }
    owner_error = SdkError::default();
    let refused = unsafe { sys::sdk_port_receive(wrong_key, port, message, &mut owner_error) };
    if !expect_raw_owner_refusal(context, refused, owner_error, aros::Operation::PortReceive) {
        return false;
    }

    let mut copied = [0xa5; 32];
    owner_error = SdkError::default();
    let refused = unsafe {
        sys::sdk_message_copy(
            wrong_key,
            message,
            copied.as_mut_ptr(),
            copied.len(),
            &mut owner_error,
        )
    };
    if !expect_raw_owner_refusal(context, refused, owner_error, aros::Operation::MessageCopy)
        || copied != [0xa5; 32]
    {
        return false;
    }
    owner_error = SdkError::default();
    let refused = unsafe { sys::sdk_message_reply(wrong_key, message, &mut owner_error) };
    if !expect_raw_owner_refusal(context, refused, owner_error, aros::Operation::MessageReply) {
        return false;
    }
    owner_error = SdkError::default();
    let refused = unsafe { sys::sdk_message_drop(wrong_key, message, &mut owner_error) };
    if !expect_raw_owner_refusal(context, refused, owner_error, aros::Operation::MessageDrop)
        || !same_resources(live, context.statistics())
    {
        return false;
    }

    owner_error = SdkError::default();
    if unsafe { sys::sdk_signal_post(context.key(), signal, &mut owner_error) } != 0
        || unsafe { sys::sdk_signal_wait(context.key(), signal, &mut owner_error) } != 0
    {
        return false;
    }
    owner_error = SdkError::default();
    if unsafe { sys::sdk_port_put(context.key(), port, message, port, &mut owner_error) } != 0 {
        return false;
    }
    owner_error = SdkError::default();
    if unsafe { sys::sdk_port_receive(context.key(), port, message, &mut owner_error) } != 1 {
        return false;
    }
    owner_error = SdkError::default();
    let copied_count = unsafe {
        sys::sdk_message_copy(
            context.key(),
            message,
            copied.as_mut_ptr(),
            copied.len(),
            &mut owner_error,
        )
    };
    let copied_message_matches = copied_count == message_bytes.len() as i32
        && &copied[..message_bytes.len()] == message_bytes;
    if !copied_message_matches {
        return false;
    }
    owner_error = SdkError::default();
    if unsafe { sys::sdk_message_reply(context.key(), message, &mut owner_error) } != 0 {
        return false;
    }
    owner_error = SdkError::default();
    if unsafe { sys::sdk_port_receive(context.key(), port, message, &mut owner_error) } != 1 {
        return false;
    }

    owner_error = SdkError::default();
    if unsafe { sys::sdk_message_drop(context.key(), message, &mut owner_error) } != 0 {
        return false;
    }
    owner_error = SdkError::default();
    if unsafe { sys::sdk_port_drop(context.key(), port, &mut owner_error) } != 0 {
        return false;
    }
    owner_error = SdkError::default();
    if unsafe { sys::sdk_signal_drop(context.key(), signal, &mut owner_error) } != 0 {
        return false;
    }
    same_resources(baseline, context.statistics())
}

fn diagnostics(context: &Context, long: bool) -> bool {
    let before = context.statistics();
    if long {
        let label = [b'x'; 512];
        context.diagnostic(&label, 0x1020_3040);
    } else {
        context.diagnostic(b"qualification-diagnostic", 0x4152_4f53);
    }
    let after = context.statistics();
    before == after
}

fn write_fixture(context: &Context, bytes: &[u8]) -> bool {
    let Some(path) = byte_path(b"RAM:ami-rust-m1/fault-fixture.bin") else {
        return false;
    };
    let mut file = match File::open(context, &path, FileMode::CreateTruncate) {
        Ok(file) => file,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    if let Err(error) = file.write_all(bytes) {
        report_error(context, error);
        return false;
    }
    match file.close() {
        Ok(()) => true,
        Err(error) => {
            report_error(context, error);
            false
        }
    }
}

fn fault_file_matches(context: &Context, expected: &[u8]) -> bool {
    if expected.len() > 4096 {
        return false;
    }
    let Some(path) = byte_path(b"RAM:ami-rust-m1/fault-fixture.bin") else {
        return false;
    };
    let mut file = match File::open(context, &path, FileMode::ReadExisting) {
        Ok(file) => file,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    let mut actual = [0u8; 4096];
    if let Err(error) = file.read_exact(&mut actual[..expected.len()]) {
        report_error(context, error);
        return false;
    }
    if &actual[..expected.len()] != expected {
        return false;
    }
    let mut extra = [0u8; 1];
    match file.read(&mut extra) {
        Ok(0) => {}
        Ok(count) => {
            context.diagnostic(b"qualification-fault-file-length", count as u64);
            return false;
        }
        Err(error) => {
            report_error(context, error);
            return false;
        }
    }
    if let Err(error) = file.close() {
        report_error(context, error);
        return false;
    }
    true
}

fn fault_mode(context: &Context, site: u32) -> bool {
    let baseline = context.statistics();
    let Some(path) = byte_path(b"RAM:ami-rust-m1/fault-fixture.bin") else {
        return false;
    };
    let mut expected = [0u8; 4096];
    fill_sequence(&mut expected, 0);

    match site {
        FAULT_ALLOC => {
            let layout = match Layout::from_size_align(64, 16) {
                Ok(layout) => layout,
                Err(_) => return false,
            };
            let allocator = aros::ExecAllocator;
            let old = unsafe { GlobalAlloc::alloc(&allocator, layout) };
            if old.is_null() {
                return false;
            }
            if !unsafe { check_or_fill_pattern(old, 64, 3, 7, true) } {
                unsafe { GlobalAlloc::dealloc(&allocator, old, layout) };
                return false;
            }
            let live = context.statistics();
            set_fault(site);
            let grown_layout = match Layout::from_size_align(128, 16) {
                Ok(layout) => layout,
                Err(_) => {
                    reset_fault();
                    unsafe { GlobalAlloc::dealloc(&allocator, old, layout) };
                    return false;
                }
            };
            let replacement = unsafe { GlobalAlloc::realloc(&allocator, old, layout, 128) };
            reset_fault();
            if !replacement.is_null() {
                unsafe { GlobalAlloc::dealloc(&allocator, replacement, grown_layout) };
                return false;
            }
            let preserved = unsafe { check_or_fill_pattern(old, 64, 3, 7, false) };
            let after_failure = context.statistics();
            let refusal_seen = after_failure.refusals == live.refusals + 1;
            let resources_retained = same_resources(live, after_failure);
            unsafe { GlobalAlloc::dealloc(&allocator, old, layout) };
            preserved
                && refusal_seen
                && resources_retained
                && same_resources(baseline, context.statistics())
        }
        FAULT_OPEN => {
            if !write_fixture(context, &expected) {
                return false;
            }
            set_fault(site);
            let result = File::open(context, &path, FileMode::CreateTruncate);
            reset_fault();
            let ok = expect_native_error(context, result, 0x1234_5678_9);
            ok && same_resources(baseline, context.statistics())
                && fault_file_matches(context, &expected)
        }
        FAULT_READ => {
            if !write_fixture(context, &expected) {
                return false;
            }
            let mut file = match File::open(context, &path, FileMode::ReadExisting) {
                Ok(file) => file,
                Err(error) => {
                    report_error(context, error);
                    return false;
                }
            };
            let mut buffer = [0u8; 8];
            set_fault(site);
            let result = file.read(&mut buffer);
            reset_fault();
            let ok = expect_native_error(context, result, 0x1234_5678_9);
            drop(file);
            ok && same_resources(baseline, context.statistics())
                && fault_file_matches(context, &expected)
        }
        FAULT_WRITE => {
            if !write_fixture(context, &expected) {
                return false;
            }
            let mut file = match File::open(context, &path, FileMode::ReadWrite) {
                Ok(file) => file,
                Err(error) => {
                    report_error(context, error);
                    return false;
                }
            };
            set_fault(site);
            let result = file.write(&expected[..8]);
            reset_fault();
            let ok = expect_native_error(context, result, 0x1234_5678_9);
            drop(file);
            ok && same_resources(baseline, context.statistics())
                && fault_file_matches(context, &expected)
        }
        FAULT_CLOSE => {
            if !write_fixture(context, &expected) {
                return false;
            }
            let file = match File::open(context, &path, FileMode::ReadExisting) {
                Ok(file) => file,
                Err(error) => {
                    report_error(context, error);
                    return false;
                }
            };
            set_fault(site);
            let result = file.close();
            reset_fault();
            let ok = expect_native_error(context, result, 0x1234_5678_9);
            ok && same_resources(baseline, context.statistics())
                && fault_file_matches(context, &expected)
        }
        FAULT_OPEN_LIBRARY => {
            let Some(name) = byte_path(b"dos.library") else {
                return false;
            };
            set_fault(site);
            let result = Library::open(context, &name, 0);
            reset_fault();
            let ok = expect_error(context, result, ErrorKind::Native);
            if !ok || !same_resources(baseline, context.statistics()) {
                return false;
            }
            match Library::open(context, &name, 0) {
                Ok(library) => {
                    drop(library);
                    same_resources(baseline, context.statistics())
                }
                Err(error) => {
                    report_error(context, error);
                    false
                }
            }
        }
        FAULT_ALLOC_SIGNAL => {
            set_fault(site);
            let result = Signal::new(context);
            reset_fault();
            if !expect_error(context, result, ErrorKind::Native)
                || !same_resources(baseline, context.statistics())
            {
                return false;
            }
            match Signal::new(context) {
                Ok(signal) => {
                    drop(signal);
                    same_resources(baseline, context.statistics())
                }
                Err(error) => {
                    report_error(context, error);
                    false
                }
            }
        }
        FAULT_CREATE_PORT => {
            set_fault(site);
            let result = Port::new(context);
            reset_fault();
            if !expect_error(context, result, ErrorKind::Native)
                || !same_resources(baseline, context.statistics())
            {
                return false;
            }
            match Port::new(context) {
                Ok(port) => {
                    drop(port);
                    same_resources(baseline, context.statistics())
                }
                Err(error) => {
                    report_error(context, error);
                    false
                }
            }
        }
        FAULT_SLOT_RESERVATION => {
            let layout = match Layout::from_size_align(64, 16) {
                Ok(layout) => layout,
                Err(_) => return false,
            };
            let grown_layout = match Layout::from_size_align(128, 16) {
                Ok(layout) => layout,
                Err(_) => return false,
            };
            let allocator = aros::ExecAllocator;
            let old = unsafe { GlobalAlloc::alloc(&allocator, layout) };
            if old.is_null() || !unsafe { check_or_fill_pattern(old, 64, 3, 7, true) } {
                if !old.is_null() {
                    unsafe { GlobalAlloc::dealloc(&allocator, old, layout) };
                }
                return false;
            }
            let allocation_live = context.statistics();
            set_fault_nth(site, 1);
            let failed_realloc = unsafe { GlobalAlloc::realloc(&allocator, old, layout, 128) };
            reset_fault();
            if !failed_realloc.is_null() {
                unsafe { GlobalAlloc::dealloc(&allocator, failed_realloc, grown_layout) };
                return false;
            }
            let allocation_preserved = unsafe { check_or_fill_pattern(old, 64, 3, 7, false) }
                && one_refusal_since(context, allocation_live);
            if !allocation_preserved {
                unsafe { GlobalAlloc::dealloc(&allocator, old, layout) };
                return false;
            }
            let recovered = unsafe { GlobalAlloc::realloc(&allocator, old, layout, 128) };
            if recovered.is_null() {
                unsafe { GlobalAlloc::dealloc(&allocator, old, layout) };
                return false;
            }
            let recovered_content = unsafe { check_or_fill_pattern(recovered, 64, 3, 7, false) };
            unsafe { GlobalAlloc::dealloc(&allocator, recovered, grown_layout) };
            if !recovered_content || !same_resources(baseline, context.statistics()) {
                return false;
            }

            let Some(name) = byte_path(b"dos.library") else {
                return false;
            };
            let before_library = context.statistics();
            set_fault_nth(site, 1);
            let result = Library::open(context, &name, 0);
            reset_fault();
            if !expect_error(context, result, ErrorKind::Limit)
                || !one_refusal_since(context, before_library)
            {
                return false;
            }
            match Library::open(context, &name, 0) {
                Ok(library) => drop(library),
                Err(error) => {
                    report_error(context, error);
                    return false;
                }
            }
            if !same_resources(baseline, context.statistics()) {
                return false;
            }

            let before_signal = context.statistics();
            set_fault_nth(site, 1);
            let result = Signal::new(context);
            reset_fault();
            if !expect_error(context, result, ErrorKind::Limit)
                || !one_refusal_since(context, before_signal)
            {
                return false;
            }
            match Signal::new(context) {
                Ok(signal) => drop(signal),
                Err(error) => {
                    report_error(context, error);
                    return false;
                }
            }
            if !same_resources(baseline, context.statistics()) {
                return false;
            }

            for nth in [1, 2] {
                let before_port = context.statistics();
                set_fault_nth(site, nth);
                let result = Port::new(context);
                reset_fault();
                if !expect_error(context, result, ErrorKind::Limit)
                    || !one_refusal_since(context, before_port)
                {
                    return false;
                }
                match Port::new(context) {
                    Ok(port) => drop(port),
                    Err(error) => {
                        report_error(context, error);
                        return false;
                    }
                }
                if !same_resources(baseline, context.statistics()) {
                    return false;
                }
            }

            let before_message = context.statistics();
            set_fault_nth(site, 1);
            let result = Message::new(context, b"slot reservation recovery");
            reset_fault();
            if !expect_error(context, result, ErrorKind::Limit)
                || !one_refusal_since(context, before_message)
            {
                return false;
            }
            match Message::new(context, b"slot reservation recovery") {
                Ok(message) => drop(message),
                Err(error) => {
                    report_error(context, error);
                    return false;
                }
            }
            if !same_resources(baseline, context.statistics()) {
                return false;
            }

            let before_file = context.statistics();
            set_fault_nth(site, 1);
            let result = File::open(context, &path, FileMode::CreateTruncate);
            reset_fault();
            if !expect_error(context, result, ErrorKind::Limit)
                || !one_refusal_since(context, before_file)
            {
                return false;
            }
            write_fixture(context, &expected)
        }
        FAULT_SHORT_READ => {
            if !write_fixture(context, &expected) {
                return false;
            }
            let mut file = match File::open(context, &path, FileMode::ReadExisting) {
                Ok(file) => file,
                Err(error) => {
                    report_error(context, error);
                    return false;
                }
            };
            let mut actual = [0u8; 4096];
            set_fault(site);
            let result = file.read_exact(&mut actual);
            reset_fault();
            let ok = result.is_ok() && actual == expected;
            if let Err(error) = result {
                report_error(context, error);
            }
            drop(file);
            ok && same_resources(baseline, context.statistics())
        }
        FAULT_SHORT_WRITE => {
            let mut file = match File::open(context, &path, FileMode::CreateTruncate) {
                Ok(file) => file,
                Err(error) => {
                    report_error(context, error);
                    return false;
                }
            };
            set_fault(site);
            let result = file.write_all(&expected);
            reset_fault();
            if let Err(error) = result {
                report_error(context, error);
                return false;
            }
            if let Err(error) = file.close() {
                report_error(context, error);
                return false;
            }
            // Keep verification storage off the allocation ledger being compared.
            let mut actual = [0u8; 4096];
            let mut file = match File::open(context, &path, FileMode::ReadExisting) {
                Ok(file) => file,
                Err(error) => {
                    report_error(context, error);
                    return false;
                }
            };
            let result = file.read_exact(&mut actual);
            let ok = result.is_ok() && actual == expected;
            if let Err(error) = result {
                report_error(context, error);
            }
            drop(file);
            ok && same_resources(baseline, context.statistics())
        }
        FAULT_ZERO_WRITE => {
            if !write_fixture(context, &expected) {
                return false;
            }
            let mut file = match File::open(context, &path, FileMode::ReadWrite) {
                Ok(file) => file,
                Err(error) => {
                    report_error(context, error);
                    return false;
                }
            };
            set_fault(site);
            let result = file.write_all(b"zero-progress-probe");
            reset_fault();
            let ok = expect_error(context, result, ErrorKind::ZeroProgress);
            drop(file);
            ok && same_resources(baseline, context.statistics())
                && fault_file_matches(context, &expected)
        }
        _ => false,
    }
}

fn prepare_live_resources(context: &Context) -> bool {
    let Some(file_path) = byte_path(b"RAM:ami-rust-m1/live-cleanup.bin") else {
        return false;
    };
    let Some(library_name) = byte_path(b"dos.library") else {
        return false;
    };
    let file = match File::open(context, &file_path, FileMode::CreateTruncate) {
        Ok(file) => file,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    let library = match Library::open(context, &library_name, 0) {
        Ok(library) => library,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    let first_port = match Port::new(context) {
        Ok(port) => port,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    let second_port = match Port::new(context) {
        Ok(port) => port,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    let mut message = match Message::new(context, b"forgotten cleanup fixture") {
        Ok(message) => message,
        Err(error) => {
            report_error(context, error);
            return false;
        }
    };
    let mut allocation = Vec::new();
    if allocation.try_reserve_exact(8192).is_err() {
        return false;
    }
    allocation.resize(8192, 0x5a);

    if let Err(error) = first_port.send(&mut message, &second_port) {
        report_error(context, error);
        return false;
    }

    let stats = context.statistics();
    if stats.blocks == 0
        || stats.files == 0
        || stats.libraries == 0
        || stats.ports < 2
        || stats.messages == 0
    {
        return false;
    }

    // These forgotten handles and allocation intentionally require cleanup at
    // the C application boundary; Rust Drop cannot establish fatal cleanup.
    mem::forget(allocation);
    mem::forget(file);
    mem::forget(library);
    mem::forget(first_port);
    mem::forget(second_port);
    mem::forget(message);
    true
}

fn ordinary_cleanup(context: &Context) -> bool {
    let before = context.statistics();
    {
        let Some(path) = byte_path(b"RAM:ami-rust-m1/ordinary-cleanup.bin") else {
            return false;
        };
        let file = match File::open(context, &path, FileMode::CreateTruncate) {
            Ok(file) => file,
            Err(error) => {
                report_error(context, error);
                return false;
            }
        };
        let Some(name) = byte_path(b"dos.library") else {
            return false;
        };
        let library = match Library::open(context, &name, 0) {
            Ok(library) => library,
            Err(error) => {
                report_error(context, error);
                return false;
            }
        };
        let port = match Port::new(context) {
            Ok(port) => port,
            Err(error) => {
                report_error(context, error);
                return false;
            }
        };
        let message = match Message::new(context, b"normal cleanup") {
            Ok(message) => message,
            Err(error) => {
                report_error(context, error);
                return false;
            }
        };
        drop(message);
        drop(port);
        drop(library);
        drop(file);
    }
    same_resources(before, context.statistics())
}

mod file_protection;
fn application(context: &Context) -> AppStatus {
    match mode(context) {
        Some("file-protected") => file_protection::run(context),
        Some("calibrate") => {
            if abi_and_callbacks(context) && diagnostics(context, false) {
                success(context, b"qualification-calibration", 0)
            } else {
                fatal(context, 2)
            }
        }
        Some("abi") => {
            if abi_and_callbacks(context) {
                success(
                    context,
                    b"qualification-abi-callback",
                    sys::ABI_LAYOUT_VALUE_COUNT as u64,
                )
            } else {
                fatal(context, 3)
            }
        }
        Some("alloc") => {
            if allocation_limits(context) {
                success(context, b"qualification-allocation-limits", 52)
            } else {
                fatal(context, 4)
            }
        }
        Some("memory-large") => {
            if large_allocations(context) {
                success(context, b"qualification-large-allocations", 2)
            } else {
                fatal(context, 23)
            }
        }
        Some("churn") => {
            if allocator_workload(context) {
                success(context, b"qualification-m0-churn", 1000)
            } else {
                fatal(context, 5)
            }
        }
        Some("files") => {
            if file_and_path_cases(context) {
                success(context, b"qualification-file-cases", 10)
            } else {
                fatal(context, 7)
            }
        }
        Some("libraries") => {
            if library_cases(context) {
                success(context, b"qualification-library-limits", 4)
            } else {
                fatal(context, 8)
            }
        }
        Some("ports") => {
            if signal_port_message_cases(context) {
                success(context, b"qualification-port-message", 10)
            } else {
                fatal(context, 9)
            }
        }
        Some("devices") => {
            if device_cases(context) {
                success(context, b"qualification-device-cases", 12)
            } else {
                fatal(context, 25)
            }
        }
        Some("devices-forgotten") => {
            if device_forgotten_cases(context) {
                success(context, b"qualification-device-forgotten", 2)
            } else {
                fatal(context, 26)
            }
        }
        Some("fs") => {
            if m2::fs_cases(context) {
                success(context, b"qualification-fs-cases", 8)
            } else {
                fatal(context, 27)
            }
        }
        Some("fs-forgotten") => {
            if m2::fs_forgotten_cases(context) {
                success(context, b"qualification-fs-forgotten", 2)
            } else {
                fatal(context, 28)
            }
        }
        Some("cwd-check") => {
            if m2::cwd_check(context) {
                success(context, b"qualification-cwd-check", 1)
            } else {
                fatal(context, 29)
            }
        }
        Some("env") => {
            if m2::env_cases(context) {
                success(context, b"qualification-env-cases", 6)
            } else {
                fatal(context, 30)
            }
        }
        Some("args") => {
            if m2::args_cases(context) {
                success(context, b"qualification-args-cases", 1)
            } else {
                fatal(context, 31)
            }
        }
        Some("timer") => {
            if m3::cases(context) {
                success(context, b"qualification-timer-cases", 9)
            } else {
                fatal(context, 32)
            }
        }
        Some("timer-measure") => {
            if m3::measure(context) {
                success(context, b"qualification-timer-measure", 2)
            } else {
                fatal(context, 33)
            }
        }
        Some("timer-forgotten") => {
            if m3::forgotten(context) {
                success(context, b"qualification-timer-forgotten", 1)
            } else {
                fatal(context, 34)
            }
        }
        Some("positions") => {
            if m2::positions(context) {
                success(context, b"qualification-positions", 1)
            } else {
                fatal(context, 35)
            }
        }
        Some("big") => {
            if m2::big(context) {
                success(context, b"qualification-big", 1)
            } else {
                fatal(context, 36)
            }
        }
        Some("info") => {
            if m2::info(context) {
                success(context, b"qualification-info", 1)
            } else {
                fatal(context, 37)
            }
        }
        Some("probes") => {
            if m4::cases(context) {
                success(context, b"qualification-probes", 6)
            } else {
                fatal(context, 38)
            }
        }
        Some("graphics") => {
            if m5::cases(context) {
                success(context, b"qualification-graphics", 7)
            } else {
                fatal(context, 39)
            }
        }
        Some("graphics-forgotten") => {
            if m5::forgotten(context) {
                success(context, b"qualification-graphics-forgotten", 3)
            } else {
                fatal(context, 40)
            }
        }
        Some("avail") => {
            if m5::available(context) {
                success(context, b"qualification-avail", 1)
            } else {
                fatal(context, 41)
            }
        }
        Some("graphics-dump") => {
            if m5::dump(context) {
                success(context, b"qualification-graphics-dump", 1)
            } else {
                fatal(context, 42)
            }
        }
        Some("registry") => {
            if registry_growth_cases(context) {
                success(context, b"qualification-registry-growth", 5)
            } else {
                fatal(context, 24)
            }
        }
        Some("callbacks") => {
            if callback_cases(context) {
                success(context, b"qualification-callbacks", 10)
            } else {
                fatal(context, 10)
            }
        }
        Some("cleanup") => {
            if ordinary_cleanup(context) {
                success(context, b"qualification-normal-cleanup", 0)
            } else {
                fatal(context, 11)
            }
        }
        Some("diagnostic") | Some("diag-normal") => {
            if diagnostics(context, false) {
                success(context, b"qualification-diagnostic-normal", 0)
            } else {
                fatal(context, 60)
            }
        }
        Some("diag-long") => {
            if diagnostics(context, true) {
                success(context, b"qualification-diagnostic-long", 512)
            } else {
                fatal(context, 61)
            }
        }
        Some("diag-direct") | Some("diag-malloc") | Some("diag-pool") => {
            context.diagnostic(b"qualification-injected-diagnostic", 1);
            AppStatus::Success
        }
        Some("fault1") => {
            if fault_mode(context, FAULT_ALLOC) {
                success(context, b"qualification-fault", 1)
            } else {
                fatal(context, 101)
            }
        }
        Some("fault2") => {
            if fault_mode(context, FAULT_OPEN) {
                success(context, b"qualification-fault", 2)
            } else {
                fatal(context, 102)
            }
        }
        Some("fault3") => {
            if fault_mode(context, FAULT_READ) {
                success(context, b"qualification-fault", 3)
            } else {
                fatal(context, 103)
            }
        }
        Some("fault4") => {
            if fault_mode(context, FAULT_WRITE) {
                success(context, b"qualification-fault", 4)
            } else {
                fatal(context, 104)
            }
        }
        Some("fault5") => {
            if fault_mode(context, FAULT_CLOSE) {
                success(context, b"qualification-fault", 5)
            } else {
                fatal(context, 105)
            }
        }
        Some("fault6") => {
            if fault_mode(context, FAULT_OPEN_LIBRARY) {
                success(context, b"qualification-fault", 6)
            } else {
                fatal(context, 106)
            }
        }
        Some("fault7") => {
            if fault_mode(context, FAULT_ALLOC_SIGNAL) {
                success(context, b"qualification-fault", 7)
            } else {
                fatal(context, 107)
            }
        }
        Some("fault8") => {
            if fault_mode(context, FAULT_CREATE_PORT) {
                success(context, b"qualification-fault", 8)
            } else {
                fatal(context, 108)
            }
        }
        Some("fault9") => {
            if fault_mode(context, FAULT_SLOT_RESERVATION) {
                success(context, b"qualification-fault", 9)
            } else {
                fatal(context, 109)
            }
        }
        Some("fault10") => {
            if fault_mode(context, FAULT_SHORT_READ) {
                success(context, b"qualification-fault", 10)
            } else {
                fatal(context, 110)
            }
        }
        Some("fault11") => {
            if fault_mode(context, FAULT_SHORT_WRITE) {
                success(context, b"qualification-fault", 11)
            } else {
                fatal(context, 111)
            }
        }
        Some("fault12") => {
            if fault_mode(context, FAULT_ZERO_WRITE) {
                success(context, b"qualification-fault", 12)
            } else {
                fatal(context, 112)
            }
        }
        Some("fault13") | Some("startup-fail") => {
            // C main must arm mandatory-DOS failure before sdk_begin. Reaching
            // Rust means the startup counter-probe did not fire.
            AppStatus::Success
        }
        Some("expected-error") => match BytePath::new(b"bad\0path") {
            Err(error) if error.kind == ErrorKind::Input => {
                report_error(context, error);
                AppStatus::Error
            }
            _ => fatal(context, 12),
        },
        Some("return-error") => {
            if prepare_live_resources(context) {
                AppStatus::Error
            } else {
                fatal(context, 13)
            }
        }
        Some("forgetnormal") => {
            if prepare_live_resources(context) {
                AppStatus::Success
            } else {
                fatal(context, 14)
            }
        }
        Some("cleanup-secondary") => {
            // The native harness arms a Close failure and a one-shot fatal
            // diagnostic. Avoid any Rust diagnostic here: the first close
            // report must occur during the C-owned cleanup drain.
            if prepare_live_resources(context) {
                AppStatus::Success
            } else {
                fatal(context, 22)
            }
        }
        Some("fatal-panic") => {
            if !prepare_live_resources(context) {
                return fatal(context, 15);
            }
            panic!("M1 fatal cleanup fixture");
        }
        Some("fatal-oom") => {
            if !prepare_live_resources(context) {
                return fatal(context, 16);
            }
            let layout = match Layout::from_size_align(4096, 8) {
                Ok(layout) => layout,
                Err(_) => return fatal(context, 17),
            };
            set_fault(FAULT_ALLOC);
            // SAFETY: a valid Layout with a deterministic native OOM injection.
            // This does not exhaust the guest or depend on a product quota.
            let refused = unsafe { GlobalAlloc::alloc(&aros::ExecAllocator, layout) };
            reset_fault();
            if !refused.is_null() {
                unsafe { GlobalAlloc::dealloc(&aros::ExecAllocator, refused, layout) };
                return fatal(context, 17);
            }
            alloc::alloc::handle_alloc_error(layout)
        }
        Some("callback-panic") => {
            if !prepare_live_resources(context) {
                return fatal(context, 18);
            }
            let mut callback = |_| -> u64 { panic!("panic inside synchronous callback") };
            let _ = aros::call(context, &mut callback, 0x4152_4f53);
            fatal(context, 19)
        }
        Some("secondaryfatal") => {
            if !prepare_live_resources(context) {
                return fatal(context, 20);
            }
            set_fault(FAULT_SECONDARY_FATAL);
            // SAFETY: the test harness arms a one-shot nested fatal during the
            // native fatal diagnostic; status 20 is the expected result.
            unsafe { sys::sdk_fatal(0x5345_434f_4e44) }
        }
        Some("fault14") => {
            if !prepare_live_resources(context) {
                return fatal(context, 21);
            }
            set_fault(FAULT_SECONDARY_FATAL);
            unsafe { sys::sdk_fatal(0x5345_434f_4e44) }
        }
        Some("stderr") => stderr::run(context),
        _ => AppStatus::Error,
    }
}

aros::entry!(application, alloc);

//! Calls with 7 to 12 arguments through the generated adapters.
//!
//! Each probe is a native function that hashes the library base and every
//! argument. A generated call must reach it with every argument in the right
//! position, the base where the ABI puts it, and the stack aligned at entry.

use core::ffi::c_void;

use aros::Context;
use aros_sys::Library;

use super::probe;

unsafe extern "C" {
    fn sdk_test_probe_function(count: u32) -> *const c_void;
    fn sdk_test_probe_entry_sp() -> usize;
}

struct Values {
    a1: u64,
    a2: u32,
    a3: *const c_void,
    a4: i32,
    a5: u16,
    a6: u8,
    a7: u64,
    a8: u32,
    a9: *const c_void,
    a10: i32,
    a11: u16,
    a12: u8,
}

fn values() -> Values {
    Values {
        a1: 0x1122_3344_5566_7788,
        a2: 0xa1b2_c3d4,
        a3: 0xdead_beef_0000_0003usize as *const c_void,
        a4: -0x1234_5678,
        a5: 0xbeef,
        a6: 0xa7,
        a7: 0xfedc_ba98_7654_3210,
        a8: 0x89ab_cdef,
        a9: 0x0123_4567_89ab_cdefusize as *const c_void,
        a10: -7,
        a11: 0x8001,
        a12: 0xff,
    }
}

/// The hash the native probes compute: the base first, then every argument
/// widened as the C side widens it.
fn expected(base: *mut Library, v: &Values, count: usize) -> u64 {
    let widened = [
        v.a1,
        u64::from(v.a2),
        v.a3 as usize as u64,
        u64::from(v.a4 as u32),
        u64::from(v.a5),
        u64::from(v.a6),
        v.a7,
        u64::from(v.a8),
        v.a9 as usize as u64,
        u64::from(v.a10 as u32),
        u64::from(v.a11),
        u64::from(v.a12),
    ];
    let mut hash = base as usize as u64;
    for value in &widened[..count] {
        hash = hash.wrapping_mul(31).wrapping_add(*value);
    }
    hash
}

pub fn cases(context: &Context) -> bool {
    // A fake library: pointer-sized vectors below the base, as for real ones.
    let mut table = [core::ptr::null::<c_void>(); 16];
    for count in 7..=12u32 {
        // SAFETY: the bridge returns a probe function for 7 to 12 arguments.
        let function = unsafe { sdk_test_probe_function(count) };
        if function.is_null() {
            return false;
        }
        table[16 - count as usize] = function;
    }
    let base = unsafe { table.as_mut_ptr().add(16) }.cast::<Library>();
    let v = values();
    macro_rules! check {
        ($count:expr, $call:ident, $($arg:ident),+) => {{
            // SAFETY: `base` has a vector table with the probe at this vector.
            let hash = unsafe { probe::$call(base, $(v.$arg),+) };
            let want = expected(base, &v, $count);
            let sp = unsafe { sdk_test_probe_entry_sp() };
            if hash != want || (sp + 8) % 16 != 0 {
                context.diagnostic(b"qualification-probe-mismatch", $count);
                context.diagnostic(b"qualification-probe-sp", sp as u64);
                return false;
            }
        }};
    }
    check!(7, probe_7, a1, a2, a3, a4, a5, a6, a7);
    check!(8, probe_8, a1, a2, a3, a4, a5, a6, a7, a8);
    check!(9, probe_9, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    check!(10, probe_10, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    check!(11, probe_11, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
    check!(
        12, probe_12, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12
    );

    // Control: two swapped arguments must change the hash, so a probe that
    // ignored positions could not pass.
    let mut swapped = values();
    core::mem::swap(&mut swapped.a7, &mut swapped.a1);
    if expected(base, &swapped, 12) == expected(base, &v, 12) {
        return false;
    }
    // SAFETY: as above.
    let hash = unsafe {
        probe::probe_7(
            base, swapped.a1, swapped.a2, swapped.a3, swapped.a4, swapped.a5, swapped.a6,
            swapped.a7,
        )
    };
    hash != expected(base, &v, 7) && hash == expected(base, &swapped, 7)
}

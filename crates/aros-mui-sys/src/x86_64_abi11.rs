use super::{Library, Object, TagItem, c_char, c_void};
use core::arch::asm;

unsafe fn vector(base: *mut Library, offset: usize) -> *const c_void {
    // SAFETY: x86-64 AROS library bases follow their negative pointer-vector table.
    unsafe { base.cast::<*const c_void>().sub(offset).read() }
}

pub(super) unsafe fn new_object_a(
    base: *mut Library,
    class_id: *const c_char,
    tags: *mut TagItem,
) -> *mut Object {
    let function = unsafe { vector(base, 5) };
    let result: *mut Object;
    // SAFETY: the pinned ABI-v11 SDK requires the live library base in r12 and
    // otherwise uses the x86-64 SysV argument and result registers.
    unsafe {
        asm!(
            "call {function}",
            function = in(reg) function,
            in("r12") base,
            in("rdi") class_id,
            in("rsi") tags,
            lateout("rax") result,
            clobber_abi("C"),
        );
    }
    result
}

pub(super) unsafe fn dispose_object(base: *mut Library, object: *mut Object) {
    let function = unsafe { vector(base, 6) };
    // SAFETY: the pinned ABI-v11 SDK requires the live library base in r12 and
    // otherwise uses the x86-64 SysV argument registers.
    unsafe {
        asm!(
            "call {function}",
            function = in(reg) function,
            in("r12") base,
            in("rdi") object,
            clobber_abi("C"),
        );
    }
}

pub(super) unsafe fn error(base: *mut Library) -> i32 {
    let function = unsafe { vector(base, 11) };
    let result: i32;
    // SAFETY: the pinned ABI-v11 SDK requires the live library base in r12.
    unsafe {
        asm!(
            "call {function}",
            function = in(reg) function,
            in("r12") base,
            lateout("eax") result,
            clobber_abi("C"),
        );
    }
    result
}

pub(super) unsafe fn set_error(base: *mut Library, error: i32) -> i32 {
    let function = unsafe { vector(base, 12) };
    let result: i32;
    // SAFETY: the pinned ABI-v11 SDK requires the live library base in r12 and
    // otherwise uses the x86-64 SysV argument and result registers.
    unsafe {
        asm!(
            "call {function}",
            function = in(reg) function,
            in("r12") base,
            in("edi") error,
            lateout("eax") result,
            clobber_abi("C"),
        );
    }
    result
}

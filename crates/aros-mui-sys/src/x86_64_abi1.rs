use super::{Library, Object, TagItem, c_char, c_void};
use core::mem;

unsafe fn vector(base: *mut Library, offset: usize) -> *const c_void {
    // SAFETY: x86-64 AROS library bases follow their negative pointer-vector table.
    unsafe { base.cast::<*const c_void>().sub(offset).read() }
}

pub(super) unsafe fn new_object_a(
    base: *mut Library,
    class_id: *const c_char,
    tags: *mut TagItem,
) -> *mut Object {
    type Function = unsafe extern "C" fn(*const c_char, *mut TagItem, *mut Library) -> *mut Object;
    // SAFETY: vector 5 and the base-last signature come from the pinned ABI-v1 SDK.
    let function: Function = unsafe { mem::transmute(vector(base, 5)) };
    // SAFETY: the public caller owns the raw MUI contract.
    unsafe { function(class_id, tags, base) }
}

pub(super) unsafe fn dispose_object(base: *mut Library, object: *mut Object) {
    type Function = unsafe extern "C" fn(*mut Object, *mut Library);
    // SAFETY: vector 6 and the base-last signature come from the pinned ABI-v1 SDK.
    let function: Function = unsafe { mem::transmute(vector(base, 6)) };
    // SAFETY: the public caller owns the raw MUI contract.
    unsafe { function(object, base) }
}

pub(super) unsafe fn error(base: *mut Library) -> i32 {
    type Function = unsafe extern "C" fn(*mut Library) -> i32;
    // SAFETY: vector 11 and the base-last signature come from the pinned ABI-v1 SDK.
    let function: Function = unsafe { mem::transmute(vector(base, 11)) };
    // SAFETY: the public caller owns the raw MUI contract.
    unsafe { function(base) }
}

pub(super) unsafe fn set_error(base: *mut Library, error: i32) -> i32 {
    type Function = unsafe extern "C" fn(i32, *mut Library) -> i32;
    // SAFETY: vector 12 and the base-last signature come from the pinned ABI-v1 SDK.
    let function: Function = unsafe { mem::transmute(vector(base, 12)) };
    // SAFETY: the public caller owns the raw MUI contract.
    unsafe { function(error, base) }
}

#![no_std]
//! Raw MUI vector calls for the selected AROS x86-64 ABI-v1 profile.

#[cfg(all(target_os = "aros", not(target_arch = "x86_64")))]
compile_error!("aros-mui-sys currently implements only the x86-64 AROS vector ABI");

use aros_sys::Library;
use core::{
    ffi::{c_char, c_void},
    mem,
};

/// Minimum muimaster.library API version used by this initial surface.
pub const MUI_API_VERSION: u16 = 19;

pub const TAG_DONE: u32 = 0;
pub const TAG_IGNORE: u32 = 1;
pub const TAG_MORE: u32 = 2;
pub const TAG_SKIP: u32 = 3;
pub const TAG_USER: u32 = 1 << 31;

/// AROS `struct TagItem` for the pinned 64-bit ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TagItem {
    pub tag: u32,
    pub data: usize,
}

impl TagItem {
    pub const fn new(tag: u32, data: usize) -> Self {
        Self { tag, data }
    }

    pub const fn done() -> Self {
        Self::new(TAG_DONE, 0)
    }
}

pub type Object = c_void;

unsafe fn vector(base: *mut Library, offset: usize) -> *const c_void {
    // SAFETY: AROS library bases follow their negative pointer-vector table.
    unsafe { base.cast::<*const c_void>().sub(offset).read() }
}

/// Calls `MUI_NewObjectA` (muimaster vector 5).
///
/// # Safety
///
/// `base` must be a live muimaster.library base of at least version 19,
/// `class_id` must be NUL terminated, and `tags` must address a valid terminated
/// AROS tag list for the complete call.
pub unsafe fn mui_new_object_a(
    base: *mut Library,
    class_id: *const c_char,
    tags: *mut TagItem,
) -> *mut Object {
    type Function = unsafe extern "C" fn(*const c_char, *mut TagItem, *mut Library) -> *mut Object;
    // SAFETY: vector 5 has the signature declared by the pinned MUI headers.
    let function: Function = unsafe { mem::transmute(vector(base, 5)) };
    // SAFETY: the caller supplies the complete native call contract.
    unsafe { function(class_id, tags, base) }
}

/// Calls `MUI_DisposeObject` (muimaster vector 6).
///
/// # Safety
///
/// `base` and `object` must be live and belong to the same MUI lifecycle.
pub unsafe fn mui_dispose_object(base: *mut Library, object: *mut Object) {
    type Function = unsafe extern "C" fn(*mut Object, *mut Library);
    // SAFETY: vector 6 has the signature declared by the pinned MUI headers.
    let function: Function = unsafe { mem::transmute(vector(base, 6)) };
    // SAFETY: the caller supplies the complete native call contract.
    unsafe { function(object, base) }
}

/// Calls `MUI_Error` (muimaster vector 11).
///
/// # Safety
///
/// `base` must be a live muimaster.library base of at least version 19.
pub unsafe fn mui_error(base: *mut Library) -> i32 {
    type Function = unsafe extern "C" fn(*mut Library) -> i32;
    // SAFETY: vector 11 has the signature declared by the pinned MUI headers.
    let function: Function = unsafe { mem::transmute(vector(base, 11)) };
    // SAFETY: the caller supplies the complete native call contract.
    unsafe { function(base) }
}

/// Calls `MUI_SetError` (muimaster vector 12).
///
/// # Safety
///
/// `base` must be a live muimaster.library base of at least version 19.
pub unsafe fn mui_set_error(base: *mut Library, error: i32) -> i32 {
    type Function = unsafe extern "C" fn(i32, *mut Library) -> i32;
    // SAFETY: vector 12 has the signature declared by the pinned MUI headers.
    let function: Function = unsafe { mem::transmute(vector(base, 12)) };
    // SAFETY: the caller supplies the complete native call contract.
    unsafe { function(error, base) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn tag_item_matches_the_pinned_64_bit_layout() {
        assert_eq!(size_of::<TagItem>(), 16);
        assert_eq!(align_of::<TagItem>(), 8);
        assert_eq!(offset_of!(TagItem, tag), 0);
        assert_eq!(offset_of!(TagItem, data), 8);
    }
}

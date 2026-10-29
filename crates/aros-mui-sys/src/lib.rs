#![no_std]
//! Raw MUI vector calls for the selected AROS x86-64 ABI profile.

#[cfg(all(target_os = "aros", not(target_arch = "x86_64")))]
compile_error!("aros-mui-sys currently implements only the x86-64 AROS vector ABI");
#[cfg(all(
    target_os = "aros",
    not(any(target_abi = "", target_abi = "abi1", target_abi = "abi11"))
))]
compile_error!("aros-mui-sys requires AROS ABI-v1 or ABI-v11");

use aros_sys::Library;
pub use aros_sys::{TAG_DONE, TAG_IGNORE, TAG_MORE, TAG_SKIP, TAG_USER, TagItem};
use core::ffi::{c_char, c_void};

#[cfg(any(not(target_os = "aros"), target_abi = "", target_abi = "abi1"))]
#[path = "x86_64_abi1.rs"]
mod backend;
#[cfg(all(target_os = "aros", target_abi = "abi11"))]
#[path = "x86_64_abi11.rs"]
mod backend;

/// Minimum muimaster.library API version used by this initial surface.
pub const MUI_API_VERSION: u16 = 19;

pub type Object = c_void;

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
    // SAFETY: the caller supplies the complete native call contract.
    unsafe { backend::new_object_a(base, class_id, tags) }
}

/// Calls `MUI_DisposeObject` (muimaster vector 6).
///
/// # Safety
///
/// `base` and `object` must be live and belong to the same MUI lifecycle.
pub unsafe fn mui_dispose_object(base: *mut Library, object: *mut Object) {
    // SAFETY: the caller supplies the complete native call contract.
    unsafe { backend::dispose_object(base, object) }
}

/// Calls `MUI_Error` (muimaster vector 11).
///
/// # Safety
///
/// `base` must be a live muimaster.library base of at least version 19.
pub unsafe fn mui_error(base: *mut Library) -> i32 {
    // SAFETY: the caller supplies the complete native call contract.
    unsafe { backend::error(base) }
}

/// Calls `MUI_SetError` (muimaster vector 12).
///
/// # Safety
///
/// `base` must be a live muimaster.library base of at least version 19.
pub unsafe fn mui_set_error(base: *mut Library, error: i32) -> i32 {
    // SAFETY: the caller supplies the complete native call contract.
    unsafe { backend::set_error(base, error) }
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

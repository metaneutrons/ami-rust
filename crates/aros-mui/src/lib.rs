#![no_std]
//! Safe MUI library and object ownership for AROS.

use aros::{BytePath, Context, Library};
use aros_mui_sys as sys;
use core::{ffi::CStr, marker::PhantomData, ptr::NonNull};

pub use sys::{TAG_DONE, TAG_IGNORE, TAG_MORE, TAG_SKIP, TAG_USER, TagItem};

const LIBRARY_NAME: &[u8] = b"muimaster.library";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Aros(aros::Error),
    LibraryBaseUnavailable,
    InvalidTagList,
    ObjectCreation,
}

impl From<aros::Error> for Error {
    fn from(value: aros::Error) -> Self {
        Self::Aros(value)
    }
}

/// An explicitly opened muimaster.library bound to its application context.
pub struct Mui<'ctx> {
    library: Library<'ctx>,
    base: NonNull<aros_sys::Library>,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Mui<'ctx> {
    pub fn open(context: &'ctx Context) -> Result<Self, Error> {
        let name = BytePath::new(LIBRARY_NAME)?;
        let library = Library::open(context, &name, sys::MUI_API_VERSION)?;
        // SAFETY: the returned pointer is retained only while `library` remains
        // owned by this value and every operation remains task-affine.
        let base = unsafe { library.raw_base() }
            .and_then(|base| NonNull::new(base.cast::<aros_sys::Library>()))
            .ok_or(Error::LibraryBaseUnavailable)?;
        Ok(Self {
            library,
            base,
            _task_affine: PhantomData,
        })
    }

    /// Creates an object while binding its lifetime to this MUI owner.
    ///
    /// # Safety
    ///
    /// Every tag and tag value must satisfy the contract of `class_id`,
    /// including the validity and lifetime of pointer-valued data. The list
    /// must not use `TAG_MORE` unless its referenced list is equally valid.
    pub unsafe fn new_object_raw<'mui>(
        &'mui self,
        class_id: &CStr,
        tags: &mut [TagItem],
    ) -> Result<Object<'mui, 'ctx>, Error> {
        if tags.last().is_none_or(|item| item.tag != TAG_DONE) {
            return Err(Error::InvalidTagList);
        }
        // SAFETY: CStr supplies the terminator, the validated mutable slice is
        // live for the synchronous call, and `self` owns the library base.
        let raw = unsafe {
            sys::mui_new_object_a(self.base.as_ptr(), class_id.as_ptr(), tags.as_mut_ptr())
        };
        let raw = NonNull::new(raw).ok_or(Error::ObjectCreation)?;
        Ok(Object {
            mui: self,
            raw,
            _task_affine: PhantomData,
        })
    }

    pub fn last_error(&self) -> i32 {
        // SAFETY: `self` owns the live library reference.
        unsafe { sys::mui_error(self.base.as_ptr()) }
    }

    pub fn set_error(&self, error: i32) -> i32 {
        // SAFETY: `self` owns the live library reference.
        unsafe { sys::mui_set_error(self.base.as_ptr(), error) }
    }

    pub fn close(self) -> Result<(), Error> {
        self.library.close().map_err(Error::Aros)
    }
}

/// An owned MUI object that cannot outlive its muimaster.library owner.
pub struct Object<'mui, 'ctx> {
    mui: &'mui Mui<'ctx>,
    raw: NonNull<sys::Object>,
    _task_affine: PhantomData<*mut ()>,
}

impl Object<'_, '_> {
    /// Returns the native object pointer for calls through `aros-mui-sys`.
    ///
    /// The pointer is borrowed and must not be disposed or retained past `self`.
    pub fn as_raw(&self) -> *mut sys::Object {
        self.raw.as_ptr()
    }
}

impl Drop for Object<'_, '_> {
    fn drop(&mut self) {
        // SAFETY: this object is uniquely owned and still borrows its live MUI
        // owner. Drop runs at most once.
        unsafe { sys::mui_dispose_object(self.mui.base.as_ptr(), self.raw.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_or_unterminated_tag_lists_are_rejected_by_the_contract() {
        assert!([].last().is_none_or(|item: &TagItem| item.tag != TAG_DONE));
        let unterminated = [TagItem::new(TAG_USER, 1)];
        assert!(unterminated.last().is_none_or(|item| item.tag != TAG_DONE));
        let terminated = [TagItem::done()];
        assert!(!terminated.last().is_none_or(|item| item.tag != TAG_DONE));
    }
}

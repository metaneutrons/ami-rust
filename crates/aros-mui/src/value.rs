use crate::{Class, Error, Object, Scope};
use alloc::{ffi::CString, vec::Vec};
use core::{ffi::CStr, marker::PhantomData, ptr::NonNull};

/// Closed or validated numeric value used by a generated MUI enum.
pub trait MuiEnum: Copy + 'static {
    fn into_raw(self) -> isize;
    fn from_raw(raw: isize) -> Option<Self>;
}

/// Explicit expert boundary for a foreign pointer retained by MUI.
///
/// The lifetime represents the caller's guarantee that the pointee remains
/// valid for the complete MUI scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForeignPtr<'scope, T> {
    pointer: NonNull<T>,
    _lifetime: PhantomData<&'scope mut T>,
}

/// Scope-owned, NULL-terminated array of C string pointers.
#[derive(Clone, Copy, Debug)]
pub struct StringArray<'scope> {
    pub(crate) pointer: NonNull<*const core::ffi::c_char>,
    pub(crate) scope: *const Scope,
    pub(crate) _lifetime: PhantomData<&'scope Scope>,
}

impl<'scope, T> ForeignPtr<'scope, T> {
    /// Wraps a foreign pointer for a typed pointer-valued MUI attribute.
    ///
    /// # Safety
    ///
    /// `pointer` must satisfy the native attribute's alignment, provenance,
    /// mutability, and retention contract for the full `'scope` lifetime.
    pub unsafe fn from_raw(pointer: *mut T) -> Option<Self> {
        NonNull::new(pointer).map(|pointer| Self {
            pointer,
            _lifetime: PhantomData,
        })
    }

    pub(crate) fn address(self) -> usize {
        self.pointer.as_ptr().addr()
    }
}

/// Value representation selected by a generated attribute.
pub trait ValueKind: 'static {
    type Input<'scope>;
    type Output<'scope>;

    #[doc(hidden)]
    fn encode<'scope>(scope: &'scope Scope, value: Self::Input<'scope>) -> Result<usize, Error>;
}

#[doc(hidden)]
pub trait DecodeValueKind: ValueKind {
    fn decode<'scope>(scope: &'scope Scope, raw: usize) -> Result<Self::Output<'scope>, Error>;
}

/// Built-in safe value representations used by generated attributes.
pub mod value {
    use core::marker::PhantomData;

    #[derive(Clone, Copy, Debug)]
    pub struct Boolean;
    #[derive(Clone, Copy, Debug)]
    pub struct Unsigned;
    #[derive(Clone, Copy, Debug)]
    pub struct Signed;
    #[derive(Clone, Copy, Debug)]
    pub struct Short;
    #[derive(Clone, Copy, Debug)]
    pub struct Byte;
    #[derive(Clone, Copy, Debug)]
    pub struct PointerSizedUnsigned;
    #[derive(Clone, Copy, Debug)]
    pub struct PointerSizedSigned;
    #[derive(Clone, Copy, Debug)]
    pub struct String;
    #[derive(Clone, Copy, Debug)]
    pub struct StringArray;
    #[derive(Clone, Copy, Debug)]
    pub struct Enumeration<E>(pub(crate) PhantomData<E>);
    #[derive(Clone, Copy, Debug)]
    pub struct Object<C>(pub(crate) PhantomData<C>);
    #[derive(Clone, Copy, Debug)]
    pub struct Foreign<T>(pub(crate) PhantomData<T>);
}

impl ValueKind for value::Boolean {
    type Input<'scope> = bool;
    type Output<'scope> = bool;

    fn encode(_: &Scope, value: bool) -> Result<usize, Error> {
        Ok(usize::from(value))
    }
}

impl DecodeValueKind for value::Boolean {
    fn decode(_: &Scope, raw: usize) -> Result<bool, Error> {
        Ok(raw != 0)
    }
}

impl ValueKind for value::Unsigned {
    type Input<'scope> = u32;
    type Output<'scope> = u32;

    fn encode(_: &Scope, value: u32) -> Result<usize, Error> {
        Ok(value as usize)
    }
}

impl DecodeValueKind for value::Unsigned {
    fn decode(_: &Scope, raw: usize) -> Result<u32, Error> {
        u32::try_from(raw).map_err(|_| Error::ValueOutOfRange)
    }
}

impl ValueKind for value::Signed {
    type Input<'scope> = i32;
    type Output<'scope> = i32;

    fn encode(_: &Scope, value: i32) -> Result<usize, Error> {
        Ok(value as isize as usize)
    }
}

impl DecodeValueKind for value::Signed {
    fn decode(_: &Scope, raw: usize) -> Result<i32, Error> {
        i32::try_from(raw as isize).map_err(|_| Error::ValueOutOfRange)
    }
}

impl ValueKind for value::Short {
    type Input<'scope> = i16;
    type Output<'scope> = i16;

    fn encode(_: &Scope, value: i16) -> Result<usize, Error> {
        Ok(value as isize as usize)
    }
}

impl DecodeValueKind for value::Short {
    fn decode(_: &Scope, raw: usize) -> Result<i16, Error> {
        i16::try_from(raw as isize).map_err(|_| Error::ValueOutOfRange)
    }
}

impl ValueKind for value::Byte {
    type Input<'scope> = u8;
    type Output<'scope> = u8;

    fn encode(_: &Scope, value: u8) -> Result<usize, Error> {
        Ok(value as usize)
    }
}

impl DecodeValueKind for value::Byte {
    fn decode(_: &Scope, raw: usize) -> Result<u8, Error> {
        u8::try_from(raw).map_err(|_| Error::ValueOutOfRange)
    }
}

impl ValueKind for value::PointerSizedUnsigned {
    type Input<'scope> = usize;
    type Output<'scope> = usize;

    fn encode(_: &Scope, value: usize) -> Result<usize, Error> {
        Ok(value)
    }
}

impl DecodeValueKind for value::PointerSizedUnsigned {
    fn decode(_: &Scope, raw: usize) -> Result<usize, Error> {
        Ok(raw)
    }
}

impl ValueKind for value::PointerSizedSigned {
    type Input<'scope> = isize;
    type Output<'scope> = isize;

    fn encode(_: &Scope, value: isize) -> Result<usize, Error> {
        Ok(value as usize)
    }
}

impl DecodeValueKind for value::PointerSizedSigned {
    fn decode(_: &Scope, raw: usize) -> Result<isize, Error> {
        Ok(raw as isize)
    }
}

impl ValueKind for value::String {
    type Input<'scope> = &'scope CStr;
    type Output<'scope> = CString;

    fn encode<'scope>(_: &'scope Scope, value: &'scope CStr) -> Result<usize, Error> {
        Ok(value.as_ptr().addr())
    }
}

impl DecodeValueKind for value::String {
    fn decode(_: &Scope, raw: usize) -> Result<CString, Error> {
        let pointer = NonNull::new(raw as *mut core::ffi::c_char).ok_or(Error::NullValue)?;
        // SAFETY: readable STRPTR attributes are specified by MUI as live,
        // NUL-terminated strings for the duration of this synchronous copy.
        let source = unsafe { CStr::from_ptr(pointer.as_ptr()) };
        let bytes = source.to_bytes_with_nul();
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Allocation)?;
        owned.extend_from_slice(bytes);
        CString::from_vec_with_nul(owned).map_err(|_| Error::NativeOperation)
    }
}

impl ValueKind for value::StringArray {
    type Input<'scope> = StringArray<'scope>;
    type Output<'scope> = StringArray<'scope>;

    fn encode<'scope>(scope: &'scope Scope, value: StringArray<'scope>) -> Result<usize, Error> {
        if !core::ptr::eq(scope, value.scope) {
            return Err(Error::WrongScope);
        }
        Ok(value.pointer.as_ptr().addr())
    }
}

impl<E: MuiEnum> ValueKind for value::Enumeration<E> {
    type Input<'scope> = E;
    type Output<'scope> = E;

    fn encode(_: &Scope, value: E) -> Result<usize, Error> {
        Ok(value.into_raw() as usize)
    }
}

impl<E: MuiEnum> DecodeValueKind for value::Enumeration<E> {
    fn decode(_: &Scope, raw: usize) -> Result<E, Error> {
        E::from_raw(raw as isize).ok_or(Error::UnknownEnumValue)
    }
}

impl<C: Class> ValueKind for value::Object<C> {
    type Input<'scope> = Object<'scope, C>;
    type Output<'scope> = Object<'scope, C>;

    fn encode<'scope>(scope: &'scope Scope, value: Object<'scope, C>) -> Result<usize, Error> {
        if !core::ptr::eq(scope, value.scope()) {
            return Err(Error::WrongScope);
        }
        Ok(value.raw().as_ptr().addr())
    }
}

impl<T: 'static> ValueKind for value::Foreign<T> {
    type Input<'scope> = ForeignPtr<'scope, T>;
    type Output<'scope> = ForeignPtr<'scope, T>;

    fn encode<'scope>(_: &'scope Scope, value: ForeignPtr<'scope, T>) -> Result<usize, Error> {
        Ok(value.address())
    }
}

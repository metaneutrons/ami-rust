//! Local and global variables.
//!
//! DOS keeps *local* variables per process and *global* variables in `ENV:`.
//! A variable's value is a byte string without NUL bytes.

use super::{BytePath, Error, Operation, fresh_sys_error};
use crate::Context;
use aros_sys as sys;

/// Largest value [`set_var`] accepts, in bytes.
pub const MAX_VAR_VALUE_BYTES: usize = 4096;

/// Which variables an operation looks at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum VarScope {
    /// Local variables first, then global ones. For a set, a local variable.
    Any = 0,
    /// Only the process's local variables.
    Local = 1,
    /// Only global variables (`ENV:`).
    Global = 2,
}

/// Copies the value of variable `name` into `out` and returns its length.
///
/// `out` must hold between 2 and 4096 bytes; the value is NUL terminated in
/// `out` as well.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, VarScope, set_var, var};
/// let name = BytePath::new(b"Language")?;
/// let mut buffer = [0u8; 64];
/// if let Ok(length) = var(context, &name, &mut buffer, VarScope::Any) {
///     context.diagnostic(&buffer[..length], 0);
/// }
/// ```
///
/// # Errors
///
/// Returns [`ErrorKind::Input`](crate::ErrorKind::Input) for a buffer outside that range, or a native
/// error, such as the variable not existing or the value not fitting `out`.
pub fn var(
    context: &Context,
    name: &BytePath,
    out: &mut [u8],
    scope: VarScope,
) -> Result<usize, Error> {
    let mut native_error = fresh_sys_error();
    let length = unsafe {
        sys::sdk_var_get(
            context.key(),
            name.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            scope as i32,
            &mut native_error,
        )
    };
    if length < 0 {
        Err(Error::native(Operation::VarGet, native_error))
    } else {
        Ok(length as usize)
    }
}

/// Sets variable `name` to `value`.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, VarScope, set_var};
/// let name = BytePath::new(b"my-setting")?;
/// set_var(context, &name, b"on", VarScope::Local)?;
/// ```
///
/// # Errors
///
/// Returns [`ErrorKind::Input`](crate::ErrorKind::Input) if `value` is longer than
/// [`MAX_VAR_VALUE_BYTES`] or contains a NUL byte, or a native error.
pub fn set_var(
    context: &Context,
    name: &BytePath,
    value: &[u8],
    scope: VarScope,
) -> Result<(), Error> {
    let mut native_error = fresh_sys_error();
    let result = unsafe {
        sys::sdk_var_set(
            context.key(),
            name.as_ptr(),
            value.as_ptr(),
            value.len(),
            scope as i32,
            &mut native_error,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::native(Operation::VarSet, native_error))
    }
}

/// Deletes variable `name`.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, VarScope, delete_var};
/// let name = BytePath::new(b"my-setting")?;
/// let _ = delete_var(context, &name, VarScope::Local);
/// ```
///
/// # Errors
///
/// Returns a native error, such as the variable not existing.
pub fn delete_var(context: &Context, name: &BytePath, scope: VarScope) -> Result<(), Error> {
    let mut native_error = fresh_sys_error();
    let result = unsafe {
        sys::sdk_var_delete(
            context.key(),
            name.as_ptr(),
            scope as i32,
            &mut native_error,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::native(Operation::VarDelete, native_error))
    }
}

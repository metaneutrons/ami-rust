//! Directories, entry information and the current directory.
//!
//! Locks and file info blocks stay inside the native bridge. A [`Dir`] is a
//! shared lock on a directory that is read entry by entry, and every lock the
//! bridge takes is released on every path, including at program end.

use core::{marker::PhantomData, mem};

use super::{BytePath, Error, Operation, fresh_sys_error};
use crate::Context;
use aros_sys::{self as sys, SdkEntry};

/// Longest entry name in bytes (without a terminating NUL).
pub const MAX_ENTRY_NAME_BYTES: usize = 107;

/// Date and time of an entry, in the units DOS stores them.
///
/// `days` counts from 1 January 1978, `minutes` from midnight and `ticks` in
/// fiftieths of a second within the minute.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DateStamp {
    /// Days since 1 January 1978.
    pub days: i32,
    /// Minutes since midnight.
    pub minutes: i32,
    /// Ticks (1/50 second) within the minute.
    pub ticks: i32,
}

/// Information about one file system entry.
///
/// On ABI-v1 sizes come from `dos64.library` when the system has it, so they
/// are 64-bit where the volume supports that. Otherwise (ABI-v11, which has no
/// `dos64`) they come from the qualified 32-bit `FileInfoBlock`; see
/// [`size_is_exact`](Self::size_is_exact).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    raw: SdkEntry,
}

impl Entry {
    /// Returns the entry's name as bytes, which need not be UTF-8.
    ///
    /// For [`metadata`] it is the final component of the path, or the volume
    /// name for a volume root.
    pub fn name(&self) -> &[u8] {
        let length = (self.raw.name_length as usize).min(MAX_ENTRY_NAME_BYTES);
        &self.raw.name[..length]
    }

    /// Returns `true` for a directory, including a volume root.
    pub const fn is_dir(&self) -> bool {
        self.raw.directory_type >= 0
    }

    /// Returns `true` for a plain file.
    pub const fn is_file(&self) -> bool {
        self.raw.directory_type < 0 && self.raw.entry_type == ST_FILE
    }

    /// Returns the size in bytes; zero for a directory.
    ///
    /// Check [`size_is_exact`](Self::size_is_exact): without `dos64.library`
    /// (ABI-v11, or an ABI-v1 system lacking it) a handler reports sizes in
    /// 32 bits.
    pub const fn size(&self) -> u64 {
        self.raw.size
    }

    /// Returns `false` when [`size`](Self::size) may be truncated: only the
    /// 32-bit size was available and it is at the 2 GiB limit, which is what a
    /// capped size looks like. It is `true` for a size that came from a 64-bit
    /// call or is below that limit.
    pub const fn size_is_exact(&self) -> bool {
        self.raw.size_exact != 0
    }

    /// Returns the DOS protection bits.
    ///
    /// The low four bits (delete, execute, write and read) are set when that
    /// action is *denied*; the others are set when allowed. The `FIBB_HOLD`
    /// bit exists only on ABI-v1.
    pub const fn protection(&self) -> u32 {
        self.raw.protection
    }

    /// Returns the last modification time.
    pub const fn modified(&self) -> DateStamp {
        DateStamp {
            days: self.raw.days,
            minutes: self.raw.minutes,
            ticks: self.raw.ticks,
        }
    }

    /// Returns the raw DOS entry type (`fib_EntryType`), such as `ST_FILE`
    /// (`-3`), `ST_USERDIR` (`2`) or `ST_SOFTLINK` (`3`).
    pub const fn entry_type(&self) -> i32 {
        self.raw.entry_type
    }
}

const ST_FILE: i32 = -3;

fn blank_entry() -> SdkEntry {
    SdkEntry::default()
}

/// A directory opened for iteration.
///
/// The handle is task-affine and borrows its creating [`Context`]. It is an
/// [`Iterator`] over the directory's entries in the order the file system
/// returns them. Each item is a `Result` because reading can fail part way.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, Dir};
/// let path = BytePath::new(b"RAM:")?;
/// let mut directories = 0u64;
/// for entry in Dir::open(context, &path)? {
///     if entry?.is_dir() {
///         directories += 1;
///     }
/// }
/// context.diagnostic(b"directories", directories);
/// ```
pub struct Dir<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Dir<'ctx> {
    /// Opens `path`, which must name a directory or volume.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Native`](crate::ErrorKind::Native) if DOS cannot lock the path or it is not
    /// a directory (the `native` field carries the DOS error), or another class
    /// if the bridge rejects the context.
    pub fn open(context: &'ctx Context, path: &BytePath) -> Result<Self, Error> {
        let mut native_error = fresh_sys_error();
        let token = unsafe { sys::sdk_dir_open(context.key(), path.as_ptr(), &mut native_error) };
        if token == 0 {
            return Err(Error::native(Operation::DirOpen, native_error));
        }
        Ok(Self {
            context,
            token,
            _task_affine: PhantomData,
        })
    }

    /// Reads the next entry, or `None` at the end of the directory.
    ///
    /// # Errors
    ///
    /// Returns a native error if DOS fails while reading.
    pub fn next_entry(&mut self) -> Result<Option<Entry>, Error> {
        let mut raw = blank_entry();
        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_dir_next(self.context.key(), self.token, &mut raw, &mut native_error)
        };
        match result {
            1 => Ok(Some(Entry { raw })),
            0 => Ok(None),
            _ => Err(Error::native(Operation::DirNext, native_error)),
        }
    }

    /// Closes the directory and releases its lock.
    ///
    /// # Errors
    ///
    /// Returns an error if the native registry rejects the handle.
    pub fn close(mut self) -> Result<(), Error> {
        let token = mem::replace(&mut self.token, 0);
        let mut native_error = fresh_sys_error();
        let result = unsafe { sys::sdk_dir_close(self.context.key(), token, &mut native_error) };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::native(Operation::DirClose, native_error))
        }
    }
}

impl Iterator for Dir<'_> {
    type Item = Result<Entry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry().transpose()
    }
}

impl Drop for Dir<'_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = fresh_sys_error();
        let _ = unsafe { sys::sdk_dir_close(self.context.key(), token, &mut native_error) };
    }
}

/// Reads the information of the entry `path` names.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, metadata};
/// let path = BytePath::new(b"RAM:notes.txt")?;
/// let entry = metadata(context, &path)?;
/// if entry.is_file() {
///     context.diagnostic(b"size", entry.size());
/// }
/// ```
///
/// # Errors
///
/// Returns a native error if DOS cannot lock or examine the path.
pub fn metadata(context: &Context, path: &BytePath) -> Result<Entry, Error> {
    let mut raw = blank_entry();
    let mut native_error = fresh_sys_error();
    let result =
        unsafe { sys::sdk_entry_info(context.key(), path.as_ptr(), &mut raw, &mut native_error) };
    if result == 0 {
        Ok(Entry { raw })
    } else {
        Err(Error::native(Operation::EntryInfo, native_error))
    }
}

/// Creates a directory. The parent must exist.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, create_dir, delete};
/// let path = BytePath::new(b"RAM:work")?;
/// create_dir(context, &path)?;
/// delete(context, &path)?; // an empty directory can be deleted
/// ```
///
/// # Errors
///
/// Returns a native error if DOS refuses, for example when the entry exists.
pub fn create_dir(context: &Context, path: &BytePath) -> Result<(), Error> {
    let mut native_error = fresh_sys_error();
    let result = unsafe { sys::sdk_make_dir(context.key(), path.as_ptr(), &mut native_error) };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::native(Operation::MakeDir, native_error))
    }
}

/// Deletes a file or an empty directory.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, delete};
/// let path = BytePath::new(b"RAM:old.txt")?;
/// let _ = delete(context, &path);
/// ```
///
/// # Errors
///
/// Returns a native error if DOS refuses, for example for a missing entry, a
/// directory that is not empty or a protected file.
pub fn delete(context: &Context, path: &BytePath) -> Result<(), Error> {
    let mut native_error = fresh_sys_error();
    let result = unsafe { sys::sdk_delete(context.key(), path.as_ptr(), &mut native_error) };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::native(Operation::Delete, native_error))
    }
}

/// Renames or moves an entry within one volume.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, rename};
/// let from = BytePath::new(b"RAM:a.txt")?;
/// let to = BytePath::new(b"RAM:b.txt")?;
/// let _ = rename(context, &from, &to);
/// ```
///
/// # Errors
///
/// Returns a native error if DOS refuses, for example for a missing source,
/// an existing target or a move across volumes.
pub fn rename(context: &Context, from: &BytePath, to: &BytePath) -> Result<(), Error> {
    let mut native_error = fresh_sys_error();
    let result =
        unsafe { sys::sdk_rename(context.key(), from.as_ptr(), to.as_ptr(), &mut native_error) };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::native(Operation::Rename, native_error))
    }
}

/// Copies the absolute path of the current directory into `out` and returns
/// its length.
///
/// `out` must hold between 2 and 4096 bytes; the result is NUL terminated in
/// `out` as well.
///
/// # Examples
///
/// ```ignore
/// # use aros::current_dir;
/// let mut buffer = [0u8; 256];
/// let length = current_dir(context, &mut buffer)?;
/// context.diagnostic(&buffer[..length], 0);
/// ```
///
/// # Errors
///
/// Returns [`ErrorKind::Input`](crate::ErrorKind::Input) for a buffer outside that range, or a native
/// error, including a buffer that is too small.
pub fn current_dir(context: &Context, out: &mut [u8]) -> Result<usize, Error> {
    let mut native_error = fresh_sys_error();
    let length = unsafe {
        sys::sdk_cwd_get(
            context.key(),
            out.as_mut_ptr(),
            out.len(),
            &mut native_error,
        )
    };
    if length < 0 {
        Err(Error::native(Operation::CurrentDir, native_error))
    } else {
        Ok(length as usize)
    }
}

/// Makes `path` the current directory of the application's task.
///
/// The change is undone when the program ends, so the launching shell keeps
/// its own directory.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, set_current_dir};
/// let path = BytePath::new(b"RAM:")?;
/// set_current_dir(context, &path)?;
/// // Relative paths now start at RAM:; the shell's directory is restored at exit.
/// ```
///
/// # Errors
///
/// Returns a native error if DOS cannot lock the path or it is not a
/// directory.
pub fn set_current_dir(context: &Context, path: &BytePath) -> Result<(), Error> {
    let mut native_error = fresh_sys_error();
    let result = unsafe { sys::sdk_cwd_set(context.key(), path.as_ptr(), &mut native_error) };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::native(Operation::SetCurrentDir, native_error))
    }
}

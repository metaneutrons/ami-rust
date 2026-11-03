#![no_std]
//! Task-affine disk objects (icons) for AROS, on `icon.library`.
//!
//! [`Icons`] opens `icon.library` through [`aros::Library`] and owns the
//! reference. From it:
//!
//! - [`DiskObject::open`] reads the icon of a file or drawer (the file
//!   `<name>.info`), [`DiskObject::default_for`] returns the system's default
//!   icon of a [`Kind`] and [`DiskObject::new`] makes a blank one;
//! - a disk object has a [`Kind`], a default tool, tool types, a stack size and
//!   a position, read with accessors and changed with `set_*` methods;
//! - [`DiskObject::put`] writes the icon as `<name>.info`;
//! - [`DiskObject::find_tool_type`] looks up `KEY=value` tool types and
//!   [`Icons::match_tool_value`] tests a value against a `A|B|C` list, as
//!   `FindToolType` and `MatchToolValue` do.
//!
//! The default tool and the tool types a program sets are copied into memory
//! the native bridge owns; the library's own values are put back before the
//! object is freed. Nothing is allocated on the Rust heap, and a disk object
//! that is forgotten is freed when the program finishes.
//!
//! ```ignore
//! # use aros_icon::{DiskObject, Icons, Kind};
//! let icons = Icons::open(context)?;
//! let mut icon = DiskObject::default_for(&icons, Kind::Project)?;
//! icon.set_default_tool(b"SYS:Utilities/MultiView")?;
//! icon.set_tool_types(&[b"MODE=fast", b"DEBUG"])?;
//! icon.put(b"RAM:notes.txt")?;
//! let mode = icon.find_tool_type(b"MODE");
//! assert_eq!(mode, Some(&b"fast"[..]));
//! assert!(icons.match_tool_value(b"fast", b"slow|fast")?);
//! ```
//!
//! # Limits
//!
//! A path is at most 127 bytes. A tool type or the default tool is at most 512
//! bytes and an icon has at most 64 tool types, none with a NUL byte.

use core::{
    ffi::{CStr, c_char, c_void},
    marker::PhantomData,
    mem, ptr,
};

use aros::{BytePath, Context, Library};
use aros_sys::{self as sys, SdkError, SdkIconInfo};

const LIBRARY_NAME: &[u8] = b"icon.library";
const MINIMUM_VERSION: u16 = 44;
const MAX_PATH: usize = 127;
const MAX_TEXT: usize = 512;
/// The most tool types an icon can be given.
pub const MAX_TOOL_TYPES: usize = 64;

/// Why an icon operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The SDK refused the operation; see the [`aros::Error`].
    Aros(aros::Error),
    /// The native bridge ran out of memory.
    OutOfMemory,
    /// An argument is out of range, for example text that is too long or has a
    /// NUL byte, or more than [`MAX_TOOL_TYPES`] tool types.
    Invalid,
    /// There is no such icon.
    NotFound,
    /// The library refused to write the icon.
    Failed,
}

impl From<aros::Error> for Error {
    fn from(error: aros::Error) -> Self {
        Self::Aros(error)
    }
}

fn refusal(error: SdkError) -> Error {
    match (error.kind, error.native) {
        (_, 103) => Error::OutOfMemory,
        (2, _) => Error::Invalid,
        _ => Error::Aros(aros::Error {
            kind: match error.kind {
                1 => aros::ErrorKind::Native,
                3 => aros::ErrorKind::Limit,
                4 => aros::ErrorKind::Owner,
                _ => aros::ErrorKind::State,
            },
            native: error.native,
            operation: aros::Operation::LibraryOpen,
        }),
    }
}

fn no_error() -> SdkError {
    SdkError { kind: 0, native: 0 }
}

/// The type of a disk object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Kind {
    /// A disk (volume).
    Disk = 1,
    /// A drawer.
    Drawer = 2,
    /// A program.
    Tool = 3,
    /// A data file.
    Project = 4,
    /// The trashcan.
    Garbage = 5,
    /// A device.
    Device = 6,
    /// A Kickstart disk.
    Kick = 7,
    /// An application icon.
    AppIcon = 8,
}

impl Kind {
    fn from_raw(raw: i32) -> Option<Self> {
        Some(match raw {
            1 => Self::Disk,
            2 => Self::Drawer,
            3 => Self::Tool,
            4 => Self::Project,
            5 => Self::Garbage,
            6 => Self::Device,
            7 => Self::Kick,
            8 => Self::AppIcon,
            _ => return None,
        })
    }
}

/// A NUL-terminated copy of a path.
struct Path {
    bytes: [u8; MAX_PATH + 1],
}

impl Path {
    fn new(path: &[u8]) -> Result<Self, Error> {
        // The bounded path type checks the length and the NUL bytes.
        let checked = BytePath::new(path).map_err(|_| Error::Invalid)?;
        let mut bytes = [0u8; MAX_PATH + 1];
        bytes[..checked.len()].copy_from_slice(path);
        Ok(Self { bytes })
    }

    fn as_ptr(&self) -> *const c_char {
        self.bytes.as_ptr().cast()
    }
}

/// An open `icon.library`.
///
/// The handle is task-affine and borrows its [`Context`]. Disk objects borrow
/// it, so the library stays open while they exist.
pub struct Icons<'ctx> {
    context: &'ctx Context,
    library: Library<'ctx>,
}

impl<'ctx> Icons<'ctx> {
    /// Opens `icon.library` (version 44 or newer).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aros`] if the library cannot be opened.
    pub fn open(context: &'ctx Context) -> Result<Self, Error> {
        let name = BytePath::new(LIBRARY_NAME)?;
        let library = Library::open(context, &name, MINIMUM_VERSION)?;
        Ok(Self { context, library })
    }

    fn base(&self) -> Result<*mut sys::Library, Error> {
        // SAFETY: the pointer is this open library's base, used immediately by
        // the owner task for its own library API.
        match unsafe { self.library.raw_base() } {
            Some(base) => Ok(base.cast()),
            None => Err(Error::Invalid),
        }
    }

    /// Returns whether `value` is one of the alternatives in `wanted`, a list
    /// such as `fast|slow` (the comparison ignores case, as `MatchToolValue`
    /// does).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for text that is too long or has a NUL byte.
    pub fn match_tool_value(&self, value: &[u8], wanted: &[u8]) -> Result<bool, Error> {
        let value = Text::new(value)?;
        let wanted = Text::new(wanted)?;
        let library = self.base()?;
        // SAFETY: both texts are NUL-terminated and outlive the call.
        let matched =
            unsafe { sys::icon::match_tool_value(library, wanted.as_ptr(), value.as_ptr()) };
        Ok(matched != 0)
    }

    /// Deletes the icon file `<path>.info`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a path that is too long or has a NUL
    /// byte and [`Error::NotFound`] if the library could not delete it.
    pub fn delete(&self, path: &[u8]) -> Result<(), Error> {
        let path = Path::new(path)?;
        let library = self.base()?;
        // SAFETY: the path is NUL-terminated and outlives the call.
        let deleted = unsafe { sys::icon::delete_disk_object(library, path.as_ptr()) };
        if deleted == 0 {
            Err(Error::NotFound)
        } else {
            Ok(())
        }
    }
}

struct Text {
    bytes: [u8; MAX_TEXT + 1],
}

impl Text {
    fn new(text: &[u8]) -> Result<Self, Error> {
        if text.len() > MAX_TEXT || text.contains(&0) {
            return Err(Error::Invalid);
        }
        let mut bytes = [0u8; MAX_TEXT + 1];
        bytes[..text.len()].copy_from_slice(text);
        Ok(Self { bytes })
    }

    fn as_ptr(&self) -> *const c_char {
        self.bytes.as_ptr().cast()
    }
}

/// A disk object: the icon of a file, drawer, disk or application.
///
/// Dropping it frees it; one that is forgotten is freed when the program
/// finishes. The handle is task-affine and cannot be sent to another task.
pub struct DiskObject<'i, 'ctx> {
    icons: &'i Icons<'ctx>,
    token: u64,
    object: *mut c_void,
    _task_affine: PhantomData<*mut ()>,
}

impl<'i, 'ctx> DiskObject<'i, 'ctx> {
    fn wrap(icons: &'i Icons<'ctx>, object: *mut c_void) -> Result<Self, Error> {
        let library = icons.base()?;
        let mut native_error = no_error();
        // SAFETY: the bridge records the object with the library base so it
        // can free it if this handle is forgotten.
        let token = unsafe {
            sys::sdk_icon_register(
                icons.context.key(),
                library.cast(),
                object,
                &mut native_error,
            )
        };
        if token == 0 {
            // SAFETY: the object is still ours and was just returned.
            unsafe { sys::icon::free_disk_object(library, object) };
            return Err(refusal(native_error));
        }
        Ok(Self {
            icons,
            token,
            object,
            _task_affine: PhantomData,
        })
    }

    /// Reads the icon of the file or drawer at `path` (the file
    /// `<path>.info`, without the `.info`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a path that is too long or has a NUL
    /// byte and [`Error::NotFound`] if there is no such icon.
    pub fn open(icons: &'i Icons<'ctx>, path: &[u8]) -> Result<Self, Error> {
        let path = Path::new(path)?;
        let library = icons.base()?;
        // SAFETY: the path is NUL-terminated and outlives the call.
        let object = unsafe { sys::icon::get_disk_object(library, path.as_ptr()) };
        if object.is_null() {
            return Err(Error::NotFound);
        }
        Self::wrap(icons, object)
    }

    /// Returns the system's default icon for `kind`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the system has none.
    pub fn default_for(icons: &'i Icons<'ctx>, kind: Kind) -> Result<Self, Error> {
        let library = icons.base()?;
        // SAFETY: valid library base.
        let object = unsafe { sys::icon::get_def_disk_object(library, kind as i32) };
        if object.is_null() {
            return Err(Error::NotFound);
        }
        Self::wrap(icons, object)
    }

    /// Makes a new, blank icon of `kind`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the library cannot make it.
    pub fn new(icons: &'i Icons<'ctx>, kind: Kind) -> Result<Self, Error> {
        let library = icons.base()?;
        // SAFETY: valid library base.
        let object = unsafe { sys::icon::new_disk_object(library, kind as u32) };
        if object.is_null() {
            return Err(Error::OutOfMemory);
        }
        Self::wrap(icons, object)
    }

    fn info(&self) -> Result<SdkIconInfo, Error> {
        let mut info = SdkIconInfo {
            kind: 0,
            stack_size: 0,
            x: 0,
            y: 0,
            default_tool: ptr::null(),
            tool_types: ptr::null(),
        };
        let mut native_error = no_error();
        // SAFETY: valid key, token and writable record.
        let read = unsafe {
            sys::sdk_icon_info(
                self.icons.context.key(),
                self.token,
                &mut info,
                &mut native_error,
            )
        };
        if read != 0 {
            return Err(refusal(native_error));
        }
        Ok(info)
    }

    /// Returns the native `struct DiskObject *`.
    ///
    /// The pointer is valid only while this disk object is alive and is meant
    /// for other safe wrappers that register an icon, such as the application
    /// icon of `aros-workbench`.
    pub const fn as_raw(&self) -> *mut c_void {
        self.object
    }

    /// Returns the type of the icon, or `None` for a type this crate does not
    /// know.
    pub fn kind(&self) -> Option<Kind> {
        Kind::from_raw(self.info().ok()?.kind)
    }

    /// Returns the default tool: the program that opens a project.
    pub fn default_tool(&self) -> Option<&[u8]> {
        let pointer = self.info().ok()?.default_tool;
        if pointer.is_null() {
            return None;
        }
        // SAFETY: a NUL-terminated string that lives as long as the object (or
        // the bridge's copy of it), which this borrow keeps alive.
        Some(unsafe { CStr::from_ptr(pointer) }.to_bytes())
    }

    /// Returns the tool types, in order, as `KEY=value` or `KEY` entries.
    pub fn tool_types(&self) -> ToolTypes<'_> {
        let array = self.info().map_or(ptr::null(), |info| info.tool_types);
        ToolTypes {
            array,
            index: 0,
            _object: PhantomData,
        }
    }

    /// Returns the value of the tool type `name`: the text after the `=` of a
    /// `NAME=value` entry, an empty text for a `NAME` entry without `=`, or
    /// `None` if there is no such entry. The comparison ignores case.
    pub fn find_tool_type(&self, name: &[u8]) -> Option<&[u8]> {
        let name = Text::new(name).ok()?;
        let array = self.info().ok()?.tool_types;
        if array.is_null() {
            return None;
        }
        let library = self.icons.base().ok()?;
        // SAFETY: the array is the object's NULL-terminated tool type array and
        // the name is NUL-terminated.
        let found = unsafe { sys::icon::find_tool_type(library, array, name.as_ptr()) };
        if found.is_null() {
            return None;
        }
        // SAFETY: the library returns a pointer into the entry, which lives as
        // long as the object, which this borrow keeps alive.
        Some(unsafe { CStr::from_ptr(found) }.to_bytes())
    }

    /// Returns the stack size a program started from this icon gets, in
    /// bytes, or 0 for the default.
    pub fn stack_size(&self) -> i32 {
        self.info().map_or(0, |info| info.stack_size)
    }

    /// Returns the icon's position in its drawer window, or `None` if it has
    /// none (the library uses a position of `i32::MIN` for that).
    pub fn position(&self) -> Option<(i32, i32)> {
        let info = self.info().ok()?;
        (info.x != i32::MIN && info.y != i32::MIN).then_some((info.x, info.y))
    }

    /// Sets the default tool (at most 512 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for text that is too long or has a NUL byte
    /// and [`Error::OutOfMemory`] if the bridge cannot copy it.
    pub fn set_default_tool(&mut self, tool: &[u8]) -> Result<(), Error> {
        if tool.len() > MAX_TEXT || tool.contains(&0) {
            return Err(Error::Invalid);
        }
        let mut native_error = no_error();
        // SAFETY: the bridge copies the text and puts the original back before
        // the library frees the object.
        let set = unsafe {
            sys::sdk_icon_set_default_tool(
                self.icons.context.key(),
                self.token,
                tool.as_ptr(),
                tool.len(),
                &mut native_error,
            )
        };
        if set != 0 {
            return Err(refusal(native_error));
        }
        Ok(())
    }

    /// Replaces the tool types (at most 64, each at most 512 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for too many or too long entries or one with
    /// a NUL byte, and [`Error::OutOfMemory`] if the bridge cannot copy them.
    pub fn set_tool_types(&mut self, types: &[&[u8]]) -> Result<(), Error> {
        if types.len() > MAX_TOOL_TYPES {
            return Err(Error::Invalid);
        }
        let mut items = [ptr::null::<u8>(); MAX_TOOL_TYPES];
        let mut lengths = [0usize; MAX_TOOL_TYPES];
        for (index, entry) in types.iter().enumerate() {
            if entry.len() > MAX_TEXT || entry.contains(&0) {
                return Err(Error::Invalid);
            }
            items[index] = entry.as_ptr();
            lengths[index] = entry.len();
        }
        let mut native_error = no_error();
        // SAFETY: the bridge copies the entries and puts the original array
        // back before the library frees the object.
        let set = unsafe {
            sys::sdk_icon_set_tool_types(
                self.icons.context.key(),
                self.token,
                items.as_ptr(),
                lengths.as_ptr(),
                types.len(),
                &mut native_error,
            )
        };
        if set != 0 {
            return Err(refusal(native_error));
        }
        Ok(())
    }

    /// Sets the stack size in bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aros`] if the bridge no longer knows the object.
    pub fn set_stack_size(&mut self, stack: i32) -> Result<(), Error> {
        let mut native_error = no_error();
        // SAFETY: valid key and token.
        let set = unsafe {
            sys::sdk_icon_set_stack(
                self.icons.context.key(),
                self.token,
                stack,
                &mut native_error,
            )
        };
        if set != 0 {
            return Err(refusal(native_error));
        }
        Ok(())
    }

    /// Writes the icon as `<path>.info`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a path that is too long or has a NUL
    /// byte and [`Error::Failed`] if the library cannot write the file.
    pub fn put(&self, path: &[u8]) -> Result<(), Error> {
        let path = Path::new(path)?;
        let library = self.icons.base()?;
        // SAFETY: the path is NUL-terminated; the object is open.
        let written = unsafe { sys::icon::put_disk_object(library, path.as_ptr(), self.object) };
        if written == 0 {
            Err(Error::Failed)
        } else {
            Ok(())
        }
    }
}

impl Drop for DiskObject<'_, '_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = no_error();
        // SAFETY: the bridge puts the library's own text back and forgets the
        // record first, so the object is freed once.
        let released =
            unsafe { sys::sdk_icon_release(self.icons.context.key(), token, &mut native_error) };
        if released == 0
            && let Ok(library) = self.icons.base()
        {
            // SAFETY: the library is open and the object is ours alone.
            unsafe { sys::icon::free_disk_object(library, self.object) };
        }
    }
}

/// The tool types of a disk object, in order.
pub struct ToolTypes<'a> {
    array: *const *const c_char,
    index: usize,
    _object: PhantomData<&'a ()>,
}

impl<'a> Iterator for ToolTypes<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.array.is_null() {
            return None;
        }
        // SAFETY: the array is NULL-terminated and, with its entries, lives as
        // long as the disk object this iterator borrows.
        let entry = unsafe { *self.array.add(self.index) };
        if entry.is_null() {
            return None;
        }
        self.index += 1;
        // SAFETY: each entry is a NUL-terminated string.
        Some(unsafe { CStr::from_ptr(entry) }.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::Kind;

    #[test]
    fn kinds_follow_the_disk_object_types() {
        assert_eq!(Kind::from_raw(4), Some(Kind::Project));
        assert_eq!(Kind::from_raw(8), Some(Kind::AppIcon));
        assert_eq!(Kind::from_raw(0), None);
        assert_eq!(Kind::from_raw(9), None);
    }
}

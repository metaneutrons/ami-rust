#![no_std]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! Task-affine catalogs and dates for AROS, on `locale.library`.
//!
//! [`Locales`] opens `locale.library` through [`aros::Library`] and owns the
//! reference. From it:
//!
//! - [`Locale::open`] opens the user's locale, or one by name. It gives the
//!   language name, the day and month names and [`format_date`](Locale::format_date),
//!   which formats a [`DateStamp`] with a template such as `%A %B %e, %Y`;
//! - [`Catalog::open`] looks up the message catalog of a program. The program
//!   keeps its **built-in default strings** in the source and asks
//!   [`Catalog::string`] for each message number with its default; the answer is
//!   the translation if a catalog for the user's language was found, and the
//!   default otherwise. [`CatalogOptions`] sets the language the defaults are
//!   in, forces another language, or asks for a minimum catalog version.
//!
//! Nothing is allocated on the Rust heap. The native bridge records every
//! locale and catalog, so one that is forgotten is closed when the program
//! finishes.
//!
//! ```ignore
//! # use aros_locale::{Catalog, CatalogOptions, DateStamp, Locale, Locales};
//! # use core::ffi::CStr;
//! let locales = Locales::open(context)?;
//! let locale = Locale::open(&locales, None)?;
//! let catalog = Catalog::open(&locales, Some(&locale), b"myapp.catalog", &CatalogOptions::new())?;
//! let title = catalog.string(1, c"Open a file");
//! context.diagnostic(b"title bytes", title.to_bytes().len() as u64);
//! let text = locale.format_date(b"%A %B %e %Y", DateStamp::from_amiga_seconds(0))?;
//! context.diagnostic(b"date bytes", text.as_bytes().len() as u64);
//! ```
//!
//! # Limits
//!
//! A catalog name, a template or a locale name is at most 127 bytes and a
//! language name at most 63, none with a NUL byte. A formatted date is at most
//! [`MAX_FORMATTED_BYTES`] bytes.

use core::{
    ffi::{CStr, c_char, c_void},
    marker::PhantomData,
    mem, ptr,
};

use aros::{BytePath, Context, Library};
use aros_sys::{self as sys, Hook, MinNode, SdkError, SdkLocaleInfo, TagItem, oc};

const LIBRARY_NAME: &[u8] = b"locale.library";
const MINIMUM_VERSION: u16 = 39;
const MAX_NAME: usize = 127;
const MAX_LANGUAGE: usize = 63;
const KIND_LOCALE: i32 = 0;
const KIND_CATALOG: i32 = 1;

/// The longest text [`Locale::format_date`] returns, in bytes.
pub const MAX_FORMATTED_BYTES: usize = 256;

/// Why a locale operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The SDK refused the operation; see the [`aros::Error`].
    Aros(aros::Error),
    /// The native bridge ran out of memory.
    OutOfMemory,
    /// An argument is out of range, for example a name that is too long or has
    /// a NUL byte, or a day or month number that does not exist.
    Invalid,
    /// The library has no such locale or string.
    NotFound,
    /// The formatted text does not fit in [`MAX_FORMATTED_BYTES`].
    TooLong,
}

impl From<aros::Error> for Error {
    fn from(error: aros::Error) -> Self {
        Self::Aros(error)
    }
}

fn refusal(error: SdkError) -> Error {
    if error.native == 103 {
        return Error::OutOfMemory;
    }
    Error::Aros(aros::Error {
        kind: match error.kind {
            1 => aros::ErrorKind::Native,
            2 => aros::ErrorKind::Input,
            3 => aros::ErrorKind::Limit,
            4 => aros::ErrorKind::Owner,
            _ => aros::ErrorKind::State,
        },
        native: error.native,
        operation: aros::Operation::LibraryOpen,
    })
}

fn no_error() -> SdkError {
    SdkError { kind: 0, native: 0 }
}

/// A NUL-terminated copy of a short name.
struct Name<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Name<N> {
    fn new(text: &[u8]) -> Result<Self, Error> {
        if text.len() >= N || text.contains(&0) {
            return Err(Error::Invalid);
        }
        let mut bytes = [0u8; N];
        bytes[..text.len()].copy_from_slice(text);
        Ok(Self { bytes })
    }

    fn as_ptr(&self) -> *const c_char {
        self.bytes.as_ptr().cast()
    }
}

/// An open `locale.library`.
///
/// The handle is task-affine and borrows its [`Context`]. Locales and
/// catalogs borrow it, so the library stays open while they exist.
pub struct Locales<'ctx> {
    context: &'ctx Context,
    library: Library<'ctx>,
}

impl<'ctx> Locales<'ctx> {
    /// Opens `locale.library` (version 39 or newer).
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

    fn register(&self, kind: i32, object: *mut c_void) -> Result<u64, Error> {
        let mut native_error = no_error();
        // SAFETY: the bridge records the object with the library base so it
        // can close it if the owning handle is forgotten.
        let token = unsafe {
            sys::sdk_locale_register(
                self.context.key(),
                kind,
                self.base()?.cast(),
                object,
                &mut native_error,
            )
        };
        if token == 0 {
            return Err(refusal(native_error));
        }
        Ok(token)
    }

    fn release(&self, token: u64) -> bool {
        let mut native_error = no_error();
        // SAFETY: the bridge forgets the object first so it is closed once.
        unsafe { sys::sdk_locale_release(self.context.key(), token, &mut native_error) == 0 }
    }
}

/// A date and time in AmigaDOS form: days since 1 January 1978, minutes since
/// midnight and ticks (fiftieths of a second) in the minute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct DateStamp {
    /// Days since 1 January 1978.
    pub days: i32,
    /// Minutes since midnight.
    pub minute: i32,
    /// Ticks (1/50 s) since the start of the minute.
    pub tick: i32,
}

impl DateStamp {
    /// Creates a date stamp from its three parts.
    pub const fn new(days: i32, minute: i32, tick: i32) -> Self {
        Self { days, minute, tick }
    }

    /// Converts seconds since 1 January 1978, the calendar clock of
    /// `timer.device`, to a date stamp.
    pub const fn from_amiga_seconds(seconds: u32) -> Self {
        Self {
            days: (seconds / 86_400) as i32,
            minute: ((seconds % 86_400) / 60) as i32,
            tick: ((seconds % 60) * 50) as i32,
        }
    }
}

/// A text produced by [`Locale::format_date`], owned by the value.
#[derive(Clone, Copy)]
pub struct Formatted {
    bytes: [u8; MAX_FORMATTED_BYTES],
    length: usize,
}

impl Formatted {
    /// Returns the text bytes (in the locale's character set).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

impl PartialEq for Formatted {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Formatted {}

impl core::fmt::Debug for Formatted {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Formatted(")?;
        for byte in self.as_bytes() {
            for escaped in core::ascii::escape_default(*byte) {
                core::fmt::Write::write_char(formatter, char::from(escaped))?;
            }
        }
        formatter.write_str(")")
    }
}

struct Sink {
    bytes: [u8; MAX_FORMATTED_BYTES],
    length: usize,
    overflow: bool,
    finished: bool,
}

unsafe extern "C" fn put_character(hook: *mut Hook, _locale: *mut c_void, token: usize) -> usize {
    // SAFETY: the hook was built by `format_date` and its data points at the
    // sink that outlives the library call.
    let sink = unsafe { &mut *(*hook).data.cast::<Sink>() };
    let character = token as u8;
    if character == 0 {
        sink.finished = true;
    } else if sink.length < MAX_FORMATTED_BYTES {
        sink.bytes[sink.length] = character;
        sink.length += 1;
    } else {
        sink.overflow = true;
    }
    0
}

/// An open locale.
///
/// Dropping it closes it; one that is forgotten is closed when the program
/// finishes. The handle is task-affine and cannot be sent to another task.
pub struct Locale<'l, 'ctx> {
    locales: &'l Locales<'ctx>,
    token: u64,
    locale: *mut c_void,
    _task_affine: PhantomData<*mut ()>,
}

impl<'l, 'ctx> Locale<'l, 'ctx> {
    /// Opens the locale called `name`, or the user's default locale for
    /// `None`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a name that is too long or has a NUL
    /// byte, and [`Error::NotFound`] if the library has no such locale.
    pub fn open(locales: &'l Locales<'ctx>, name: Option<&[u8]>) -> Result<Self, Error> {
        let copy = match name {
            Some(name) => Some(Name::<{ MAX_NAME + 1 }>::new(name)?),
            None => None,
        };
        let library = locales.base()?;
        // SAFETY: the name is null or NUL-terminated and outlives the call.
        let locale = unsafe {
            sys::locale::open_locale(library, copy.as_ref().map_or(ptr::null(), Name::as_ptr))
        };
        if locale.is_null() {
            return Err(Error::NotFound);
        }
        let token = match locales.register(KIND_LOCALE, locale) {
            Ok(token) => token,
            Err(error) => {
                // SAFETY: the locale is still ours and was just opened.
                unsafe { sys::locale::close_locale(library, locale) };
                return Err(error);
            }
        };
        Ok(Self {
            locales,
            token,
            locale,
            _task_affine: PhantomData,
        })
    }

    fn text(&self, number: u32) -> Result<&[u8], Error> {
        let library = self.locales.base()?;
        // SAFETY: valid library base and locale.
        let text = unsafe { sys::locale::get_locale_str(library, self.locale, number) };
        if text.is_null() {
            return Err(Error::NotFound);
        }
        // SAFETY: the library returns a NUL-terminated string that lives as
        // long as the locale, which this borrow keeps open.
        Ok(unsafe { CStr::from_ptr(text) }.to_bytes())
    }

    fn info(&self) -> Result<SdkLocaleInfo, Error> {
        let mut info = SdkLocaleInfo {
            locale_name: ptr::null(),
            language_name: ptr::null(),
            preferred: [ptr::null(); 10],
            gmt_offset: 0,
        };
        let mut native_error = no_error();
        // SAFETY: valid key, token and writable record.
        let read = unsafe {
            sys::sdk_locale_info(
                self.locales.context.key(),
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

    fn field(&self, pointer: *const c_char) -> Option<&[u8]> {
        if pointer.is_null() {
            return None;
        }
        // SAFETY: the library keeps these strings for as long as the locale is
        // open, which this borrow guarantees; they are NUL-terminated.
        Some(unsafe { CStr::from_ptr(pointer) }.to_bytes())
    }

    /// Returns the name of the language driver of the locale, for example
    /// `english.language`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the locale has none.
    pub fn language_name(&self) -> Result<&[u8], Error> {
        self.field(self.info()?.language_name)
            .ok_or(Error::NotFound)
    }

    /// Returns the name of the locale, for example `deutsch`, or `None` for
    /// the built-in locale.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aros`] if the bridge no longer knows the locale.
    pub fn locale_name(&self) -> Result<Option<&[u8]>, Error> {
        Ok(self.field(self.info()?.locale_name))
    }

    /// Returns the user's `index`th preferred language (0 to 9), most
    /// preferred first, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for an index above 9.
    pub fn preferred_language(&self, index: usize) -> Result<Option<&[u8]>, Error> {
        if index > 9 {
            return Err(Error::Invalid);
        }
        Ok(self.field(self.info()?.preferred[index]))
    }

    /// Returns the offset of local time from GMT in minutes, positive for
    /// zones west of Greenwich.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aros`] if the bridge no longer knows the locale.
    pub fn gmt_offset_minutes(&self) -> Result<i32, Error> {
        Ok(self.info()?.gmt_offset)
    }

    /// Returns the name of a weekday: 0 is Sunday and 6 is Saturday.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a number above 6.
    pub fn day_name(&self, weekday: u8) -> Result<&[u8], Error> {
        if weekday > 6 {
            return Err(Error::Invalid);
        }
        self.text(oc::DAY_1 + u32::from(weekday))
    }

    /// Returns the abbreviated name of a weekday: 0 is Sunday.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a number above 6.
    pub fn short_day_name(&self, weekday: u8) -> Result<&[u8], Error> {
        if weekday > 6 {
            return Err(Error::Invalid);
        }
        self.text(oc::ABDAY_1 + u32::from(weekday))
    }

    /// Returns the name of a month: 0 is January and 11 is December.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a number above 11.
    pub fn month_name(&self, month: u8) -> Result<&[u8], Error> {
        if month > 11 {
            return Err(Error::Invalid);
        }
        self.text(oc::MON_1 + u32::from(month))
    }

    /// Returns the abbreviated name of a month: 0 is January.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a number above 11.
    pub fn short_month_name(&self, month: u8) -> Result<&[u8], Error> {
        if month > 11 {
            return Err(Error::Invalid);
        }
        self.text(oc::ABMON_1 + u32::from(month))
    }

    /// Returns the locale's word for yes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the library has no such string.
    pub fn yes_text(&self) -> Result<&[u8], Error> {
        self.text(oc::YES_STR)
    }

    /// Returns the locale's word for no.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the library has no such string.
    pub fn no_text(&self) -> Result<&[u8], Error> {
        self.text(oc::NO_STR)
    }

    /// Formats a date with `template` (at most 127 bytes), in the locale's
    /// language.
    ///
    /// The template uses the `FormatDate` codes, for example `%A` the weekday
    /// name, `%B` the month name, `%d` or `%e` the day, `%Y` the year, `%H`,
    /// `%M` and `%S` the time and `%x` the locale's date format.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a template that is too long or has a NUL
    /// byte, and [`Error::TooLong`] if the text does not fit in
    /// [`MAX_FORMATTED_BYTES`].
    pub fn format_date(&self, template: &[u8], date: DateStamp) -> Result<Formatted, Error> {
        let template = Name::<{ MAX_NAME + 1 }>::new(template)?;
        let library = self.locales.base()?;
        let mut sink = Sink {
            bytes: [0; MAX_FORMATTED_BYTES],
            length: 0,
            overflow: false,
            finished: false,
        };
        let hook = Hook {
            min_node: MinNode {
                successor: ptr::null_mut(),
                predecessor: ptr::null_mut(),
            },
            entry: put_character as *mut c_void,
            sub_entry: ptr::null_mut(),
            data: ptr::addr_of_mut!(sink).cast(),
        };
        // SAFETY: the template is NUL-terminated, the date and the hook (whose
        // data is the sink) live through the call, and the hook entry takes
        // the hook, the locale and the character like every AROS hook.
        unsafe {
            sys::locale::format_date(
                library,
                self.locale,
                template.as_ptr(),
                ptr::addr_of!(date).cast(),
                &hook,
            );
        }
        if sink.overflow {
            return Err(Error::TooLong);
        }
        if !sink.finished {
            return Err(Error::NotFound);
        }
        Ok(Formatted {
            bytes: sink.bytes,
            length: sink.length,
        })
    }
}

impl Drop for Locale<'_, '_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token != 0
            && self.locales.release(token)
            && let Ok(library) = self.locales.base()
        {
            // SAFETY: the library is open and the locale is ours alone.
            unsafe { sys::locale::close_locale(library, self.locale) };
        }
    }
}

/// How [`Catalog::open`] finds a catalog.
#[derive(Clone, Copy, Debug)]
pub struct CatalogOptions<'t> {
    built_in_language: &'t [u8],
    language: Option<&'t [u8]>,
    version: u32,
}

impl Default for CatalogOptions<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'t> CatalogOptions<'t> {
    /// The defaults: the program's built-in strings are in English, the
    /// catalog is looked up for the languages the locale prefers, and any
    /// version is accepted.
    pub const fn new() -> Self {
        Self {
            built_in_language: b"english",
            language: None,
            version: 0,
        }
    }

    /// Sets the language the program's built-in default strings are in (at
    /// most 63 bytes). If it is the language being looked up, no catalog is
    /// loaded and the defaults are used.
    #[must_use]
    pub const fn built_in_language(mut self, language: &'t [u8]) -> Self {
        self.built_in_language = language;
        self
    }

    /// Looks up the catalog for this language (at most 63 bytes, for example
    /// `deutsch`) instead of the locale's preferred languages.
    #[must_use]
    pub const fn language(mut self, language: &'t [u8]) -> Self {
        self.language = Some(language);
        self
    }

    /// Asks for a catalog of at least this version.
    #[must_use]
    pub const fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }
}

/// A message catalog, or the lack of one.
///
/// [`Catalog::open`] succeeds even when no catalog exists for the language, as
/// is normal when the user's language is the program's own; then
/// [`string`](Self::string) returns the built-in defaults. Dropping the
/// catalog closes it; a forgotten one is closed when the program finishes.
pub struct Catalog<'l, 'ctx> {
    locales: &'l Locales<'ctx>,
    token: u64,
    catalog: *mut c_void,
    _task_affine: PhantomData<*mut ()>,
}

impl<'l, 'ctx> Catalog<'l, 'ctx> {
    /// Looks up the catalog `name` (at most 127 bytes, for example
    /// `myapp.catalog`) for `locale`, or the default locale for `None`.
    ///
    /// The library looks in `PROGDIR:Catalogs/<language>/` and then in
    /// `LOCALE:Catalogs/<language>/` for each language in turn.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a name or language that is too long or
    /// has a NUL byte, and [`Error::OutOfMemory`] if the bridge cannot record
    /// the catalog.
    pub fn open(
        locales: &'l Locales<'ctx>,
        locale: Option<&Locale<'_, 'ctx>>,
        name: &[u8],
        options: &CatalogOptions<'_>,
    ) -> Result<Self, Error> {
        let name = Name::<{ MAX_NAME + 1 }>::new(name)?;
        let built_in = Name::<{ MAX_LANGUAGE + 1 }>::new(options.built_in_language)?;
        let language = match options.language {
            Some(language) => Some(Name::<{ MAX_LANGUAGE + 1 }>::new(language)?),
            None => None,
        };
        let mut tags = [TagItem::new(sys::TAG_DONE, 0); 4];
        let mut count = 0;
        let mut push = |tag: u32, data: usize| {
            tags[count] = TagItem::new(tag, data);
            count += 1;
        };
        push(oc::BUILT_IN_LANGUAGE, built_in.as_ptr() as usize);
        if let Some(language) = &language {
            push(oc::LANGUAGE, language.as_ptr() as usize);
        }
        if options.version != 0 {
            push(oc::VERSION, options.version as usize);
        }
        let library = locales.base()?;
        // SAFETY: the name and the tag strings are NUL-terminated and outlive
        // the call (the library compares them and copies the name); the
        // locale is open or null.
        let catalog = unsafe {
            sys::locale::open_catalog_a(
                library,
                locale.map_or(ptr::null(), |locale| locale.locale.cast_const()),
                name.as_ptr(),
                tags.as_ptr(),
            )
        };
        let token = if catalog.is_null() {
            0
        } else {
            match locales.register(KIND_CATALOG, catalog) {
                Ok(token) => token,
                Err(error) => {
                    // SAFETY: the catalog is still ours and was just opened.
                    unsafe { sys::locale::close_catalog(library, catalog) };
                    return Err(error);
                }
            }
        };
        Ok(Self {
            locales,
            token,
            catalog,
            _task_affine: PhantomData,
        })
    }

    /// Returns whether a catalog was found. When it is `false`,
    /// [`string`](Self::string) always returns the built-in default.
    pub fn is_translated(&self) -> bool {
        !self.catalog.is_null()
    }

    /// Returns the text of message `id`: the catalog's translation if there is
    /// a catalog that has it, otherwise `default`.
    pub fn string<'a>(&'a self, id: u32, default: &'a CStr) -> &'a CStr {
        if self.catalog.is_null() {
            return default;
        }
        let Ok(library) = self.locales.base() else {
            return default;
        };
        // SAFETY: valid library base and catalog; `default` is NUL-terminated.
        let text = unsafe {
            sys::locale::get_catalog_str(library, self.catalog.cast_const(), id, default.as_ptr())
        };
        if text.is_null() {
            return default;
        }
        // SAFETY: the library returns the default pointer or a NUL-terminated
        // string in the catalog, which this borrow keeps open.
        unsafe { CStr::from_ptr(text) }
    }
}

impl Drop for Catalog<'_, '_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token != 0
            && self.locales.release(token)
            && let Ok(library) = self.locales.base()
        {
            // SAFETY: the library is open and the catalog is ours alone.
            unsafe { sys::locale::close_catalog(library, self.catalog) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DateStamp;

    #[test]
    fn date_stamp_from_amiga_seconds() {
        assert_eq!(DateStamp::from_amiga_seconds(0), DateStamp::new(0, 0, 0));
        // 2000-02-29 12:34:56 is 8094 days, 754 minutes and 56 seconds in.
        assert_eq!(
            DateStamp::from_amiga_seconds(699_366_896),
            DateStamp::new(8094, 754, 2800)
        );
        assert_eq!(
            DateStamp::from_amiga_seconds(86_399),
            DateStamp::new(0, 1439, 2950)
        );
        assert_eq!(
            DateStamp::from_amiga_seconds(86_400),
            DateStamp::new(1, 0, 0)
        );
    }
}

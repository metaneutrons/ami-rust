#![no_std]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! Task-affine file requesters for AROS, on `asl.library`.
//!
//! [`Asl`] opens `asl.library` through [`aros::Library`] and owns the
//! reference. [`FileRequestBuilder`] describes a file requester (title, initial
//! drawer, file and pattern, save mode, multi-selection, drawers only, position
//! and size) and [`build`](FileRequestBuilder::build) allocates it as a
//! [`FileRequester`]. [`FileRequester::request`] shows it, blocks the task until
//! the user confirms or cancels, and returns an [`Outcome`]: the selected paths
//! as owned [`AslPath`] values, or a cancellation.
//!
//! A requester can be shown again and starts where it ended unless the builder
//! set an initial drawer or file. A parent window from `aros-intuition` can be
//! given at each request; it sleeps while the requester is open. A requester is
//! freed when it is dropped, and one that is forgotten is freed when the
//! program finishes.
//!
//! ```ignore
//! # use aros_asl::{Asl, FileRequestBuilder, Outcome};
//! let asl = Asl::open(context)?;
//! let mut requester = FileRequestBuilder::new()
//!     .title(b"Open a file")
//!     .initial_drawer(b"RAM:")
//!     .build(&asl)?;
//! match requester.request(None)? {
//!     Outcome::Accepted(selection) => {
//!         let path = selection.path(0)?;
//!         context.diagnostic(b"selected bytes", path.len() as u64);
//!     }
//!     Outcome::Cancelled => {}
//! }
//! ```
//!
//! # Limits
//!
//! A path is at most [`MAX_PATH_BYTES`] bytes. Text arguments are copied into
//! the builder: a title is at most 127 bytes, a drawer 255, a file 107, a
//! pattern 63 and a button label 31, none with a NUL byte. The builder sets at
//! most 24 tags.

use core::{ffi::c_void, marker::PhantomData, mem, ptr};

use aros::{BytePath, Context, Library};
use aros_intuition::Window;
use aros_sys::{self as sys, SdkError, TagItem, aslfr};

const LIBRARY_NAME: &[u8] = b"asl.library";
const MINIMUM_VERSION: u16 = 36;
const MAX_TITLE: usize = 127;
const MAX_DRAWER: usize = 255;
const MAX_FILE: usize = 107;
const MAX_PATTERN: usize = 63;
const MAX_LABEL: usize = 31;
const MAX_TAGS: usize = 24;

/// The longest path an [`AslPath`] holds, in bytes.
pub const MAX_PATH_BYTES: usize = 512;

/// Why a requester operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The SDK refused the operation; see the [`aros::Error`].
    Aros(aros::Error),
    /// The native bridge ran out of memory.
    OutOfMemory,
    /// An argument is out of range, for example text that is too long or has a
    /// NUL byte, or a selection index past the end.
    Invalid,
    /// The library could not allocate the requester.
    Failed,
    /// A selected path is longer than [`MAX_PATH_BYTES`].
    PathTooLong,
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
        (3, _) => Error::PathTooLong,
        _ => Error::Aros(aros::Error {
            kind: match error.kind {
                1 => aros::ErrorKind::Native,
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

/// A selected path, owned by the value.
///
/// The bytes are the path as DOS gives it, for example `RAM:Work/file.txt`.
/// Use [`as_byte_path`](Self::as_byte_path) to open it with `aros::File`.
#[derive(Clone, Copy)]
pub struct AslPath {
    bytes: [u8; MAX_PATH_BYTES],
    length: usize,
}

impl AslPath {
    /// Returns the path bytes without a terminator.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    /// Returns the length in bytes.
    pub const fn len(&self) -> usize {
        self.length
    }

    /// Returns whether the path is empty.
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the path as a [`BytePath`], the form `aros` file calls take.
    ///
    /// # Errors
    ///
    /// Returns an [`aros::ErrorKind::Limit`] error for a path of more than 127
    /// bytes, which `aros` does not accept.
    pub fn as_byte_path(&self) -> Result<BytePath, aros::Error> {
        BytePath::new(self.as_bytes())
    }
}

impl PartialEq for AslPath {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for AslPath {}

impl core::fmt::Debug for AslPath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AslPath(")?;
        for byte in self.as_bytes() {
            for escaped in core::ascii::escape_default(*byte) {
                core::fmt::Write::write_char(formatter, char::from(escaped))?;
            }
        }
        formatter.write_str(")")
    }
}

/// An open `asl.library`.
///
/// The handle is task-affine and borrows its [`Context`]. Requesters borrow
/// it, so the library stays open while they exist.
pub struct Asl<'ctx> {
    context: &'ctx Context,
    library: Library<'ctx>,
}

impl<'ctx> Asl<'ctx> {
    /// Opens `asl.library` (version 36 or newer).
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
}

/// A NUL-terminated text of at most `N - 1` bytes, kept inline.
#[derive(Clone, Copy, Debug)]
struct Text<const N: usize> {
    bytes: [u8; N],
    set: bool,
}

impl<const N: usize> Text<N> {
    fn new(text: &[u8]) -> Result<Self, Error> {
        if text.len() >= N || text.contains(&0) {
            return Err(Error::Invalid);
        }
        let mut bytes = [0u8; N];
        bytes[..text.len()].copy_from_slice(text);
        Ok(Self {
            bytes,
            set: !text.is_empty(),
        })
    }

    fn tag(&self, tag: u32) -> Option<TagItem> {
        self.set
            .then(|| TagItem::new(tag, self.bytes.as_ptr() as usize))
    }
}

/// Describes a file requester.
///
/// The defaults are an open requester for one file, with no initial drawer or
/// file, the library's own title and no patterns. Text is copied into the
/// builder and checked by [`build`](Self::build).
#[derive(Clone, Copy, Debug)]
pub struct FileRequestBuilder<'t> {
    title: &'t [u8],
    drawer: &'t [u8],
    file: &'t [u8],
    pattern: &'t [u8],
    positive: &'t [u8],
    negative: &'t [u8],
    position: Option<(i16, i16)>,
    size: Option<(u16, u16)>,
    save: bool,
    multi_select: bool,
    patterns: bool,
    drawers_only: bool,
    reject_icons: bool,
}

impl Default for FileRequestBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'t> FileRequestBuilder<'t> {
    /// Creates a builder with the defaults.
    pub const fn new() -> Self {
        Self {
            title: b"",
            drawer: b"",
            file: b"",
            pattern: b"",
            positive: b"",
            negative: b"",
            position: None,
            size: None,
            save: false,
            multi_select: false,
            patterns: false,
            drawers_only: false,
            reject_icons: false,
        }
    }

    /// Sets the window title (at most 127 bytes).
    #[must_use]
    pub const fn title(mut self, title: &'t [u8]) -> Self {
        self.title = title;
        self
    }

    /// Sets the drawer the requester starts in (at most 255 bytes).
    #[must_use]
    pub const fn initial_drawer(mut self, drawer: &'t [u8]) -> Self {
        self.drawer = drawer;
        self
    }

    /// Sets the file name the requester starts with (at most 107 bytes).
    #[must_use]
    pub const fn initial_file(mut self, file: &'t [u8]) -> Self {
        self.file = file;
        self
    }

    /// Sets the pattern that filters the file list (at most 63 bytes) and shows
    /// the pattern gadget.
    #[must_use]
    pub const fn initial_pattern(mut self, pattern: &'t [u8]) -> Self {
        self.pattern = pattern;
        self.patterns = true;
        self
    }

    /// Sets the label of the confirm button (at most 31 bytes).
    #[must_use]
    pub const fn positive_text(mut self, text: &'t [u8]) -> Self {
        self.positive = text;
        self
    }

    /// Sets the label of the cancel button (at most 31 bytes).
    #[must_use]
    pub const fn negative_text(mut self, text: &'t [u8]) -> Self {
        self.negative = text;
        self
    }

    /// Sets the initial position of the requester window.
    #[must_use]
    pub const fn position(mut self, left: i16, top: i16) -> Self {
        self.position = Some((left, top));
        self
    }

    /// Sets the initial size of the requester window.
    #[must_use]
    pub const fn size(mut self, width: u16, height: u16) -> Self {
        self.size = Some((width, height));
        self
    }

    /// Asks for a file to save to: the requester allows names that do not
    /// exist yet.
    #[must_use]
    pub const fn save_mode(mut self, on: bool) -> Self {
        self.save = on;
        self
    }

    /// Allows selecting more than one file.
    #[must_use]
    pub const fn multi_select(mut self, on: bool) -> Self {
        self.multi_select = on;
        self
    }

    /// Shows the pattern gadget even without an initial pattern.
    #[must_use]
    pub const fn patterns(mut self, on: bool) -> Self {
        self.patterns = on;
        self
    }

    /// Selects a drawer instead of a file.
    #[must_use]
    pub const fn drawers_only(mut self, on: bool) -> Self {
        self.drawers_only = on;
        self
    }

    /// Hides `.info` files from the list.
    #[must_use]
    pub const fn reject_icons(mut self, on: bool) -> Self {
        self.reject_icons = on;
        self
    }

    /// Allocates the requester.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for text that is too long or has a NUL byte,
    /// [`Error::Failed`] if the library cannot allocate the requester and
    /// [`Error::OutOfMemory`] if the bridge cannot record it.
    pub fn build<'a, 'ctx>(&self, asl: &'a Asl<'ctx>) -> Result<FileRequester<'a, 'ctx>, Error> {
        let config = Config {
            title: Text::new(self.title)?,
            drawer: Text::new(self.drawer)?,
            file: Text::new(self.file)?,
            pattern: Text::new(self.pattern)?,
            positive: Text::new(self.positive)?,
            negative: Text::new(self.negative)?,
            position: self.position,
            size: self.size,
            save: self.save,
            multi_select: self.multi_select,
            patterns: self.patterns,
            drawers_only: self.drawers_only,
            reject_icons: self.reject_icons,
        };
        let library = asl.base()?;
        // SAFETY: the library base is open; no tags are passed.
        let request =
            unsafe { sys::asl::alloc_asl_request(library, aslfr::FILE_REQUEST, ptr::null_mut()) };
        if request.is_null() {
            return Err(Error::Failed);
        }
        let mut native_error = no_error();
        // SAFETY: the bridge records the requester with the library base so it
        // can free it if this handle is forgotten.
        let token = unsafe {
            sys::sdk_asl_register(
                asl.context.key(),
                library.cast(),
                request,
                &mut native_error,
            )
        };
        if token == 0 {
            // SAFETY: the requester is still ours and was just allocated.
            unsafe { sys::asl::free_asl_request(library, request) };
            return Err(refusal(native_error));
        }
        Ok(FileRequester {
            asl,
            token,
            request,
            config,
            _task_affine: PhantomData,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct Config {
    title: Text<{ MAX_TITLE + 1 }>,
    drawer: Text<{ MAX_DRAWER + 1 }>,
    file: Text<{ MAX_FILE + 1 }>,
    pattern: Text<{ MAX_PATTERN + 1 }>,
    positive: Text<{ MAX_LABEL + 1 }>,
    negative: Text<{ MAX_LABEL + 1 }>,
    position: Option<(i16, i16)>,
    size: Option<(u16, u16)>,
    save: bool,
    multi_select: bool,
    patterns: bool,
    drawers_only: bool,
    reject_icons: bool,
}

/// A file requester.
///
/// Dropping it frees the requester; a forgotten one is freed when the program
/// finishes. The handle is task-affine and cannot be sent to another task.
pub struct FileRequester<'a, 'ctx> {
    asl: &'a Asl<'ctx>,
    token: u64,
    request: *mut c_void,
    config: Config,
    _task_affine: PhantomData<*mut ()>,
}

/// The result of showing a requester.
///
/// An accepted selection borrows the requester mutably until it is dropped, so
/// the requester cannot be shown again while the paths are being read.
///
/// ```compile_fail
/// use aros_asl::{Asl, FileRequestBuilder};
///
/// fn twice(context: &aros::Context) {
///     let asl = Asl::open(context).unwrap();
///     let mut requester = FileRequestBuilder::new().build(&asl).unwrap();
///     let first = requester.request(None).unwrap();
///     let second = requester.request(None);
///     drop(first);
///     drop(second);
/// }
/// ```
pub enum Outcome<'r, 'a, 'ctx> {
    /// The user confirmed a selection.
    Accepted(Selection<'r, 'a, 'ctx>),
    /// The user cancelled, closed the window, or the requester could not open.
    Cancelled,
}

impl<'a, 'ctx> FileRequester<'a, 'ctx> {
    /// Shows the requester and blocks until the user confirms or cancels.
    ///
    /// With a `parent`, the requester opens on the parent's screen and the
    /// parent sleeps until the requester closes. The call blocks the whole
    /// task: nothing else, including other windows' events, is handled while
    /// it waits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aros`] if the bridge no longer knows the requester.
    pub fn request<'r>(
        &'r mut self,
        parent: Option<&Window<'_, '_>>,
    ) -> Result<Outcome<'r, 'a, 'ctx>, Error> {
        let library = self.asl.base()?;
        let config = &self.config;
        let mut tags = [TagItem::new(sys::TAG_DONE, 0); MAX_TAGS + 1];
        let mut count = 0;
        let mut push = |item: Option<TagItem>| {
            if let Some(item) = item {
                tags[count] = item;
                count += 1;
            }
        };
        push(config.title.tag(aslfr::TITLE_TEXT));
        push(config.drawer.tag(aslfr::INITIAL_DRAWER));
        push(config.file.tag(aslfr::INITIAL_FILE));
        push(config.pattern.tag(aslfr::INITIAL_PATTERN));
        push(config.positive.tag(aslfr::POSITIVE_TEXT));
        push(config.negative.tag(aslfr::NEGATIVE_TEXT));
        if let Some((left, top)) = config.position {
            push(Some(TagItem::new(
                aslfr::INITIAL_LEFT_EDGE,
                left as isize as usize,
            )));
            push(Some(TagItem::new(
                aslfr::INITIAL_TOP_EDGE,
                top as isize as usize,
            )));
        }
        if let Some((width, height)) = config.size {
            push(Some(TagItem::new(aslfr::INITIAL_WIDTH, usize::from(width))));
            push(Some(TagItem::new(
                aslfr::INITIAL_HEIGHT,
                usize::from(height),
            )));
        }
        for (on, tag) in [
            (config.save, aslfr::DO_SAVE_MODE),
            (config.multi_select, aslfr::DO_MULTI_SELECT),
            (config.patterns, aslfr::DO_PATTERNS),
            (config.drawers_only, aslfr::DRAWERS_ONLY),
            (config.reject_icons, aslfr::REJECT_ICONS),
        ] {
            push(on.then(|| TagItem::new(tag, 1)));
        }
        if let Some(parent) = parent {
            push(Some(TagItem::new(aslfr::WINDOW, parent.as_raw() as usize)));
            push(Some(TagItem::new(aslfr::SLEEP_WINDOW, 1)));
        }
        // SAFETY: the tag list is terminated and, with the strings it points
        // to (which live in `self`), outlives the call; the requester and the
        // parent window are open.
        let accepted = unsafe { sys::asl::asl_request(library, self.request, tags.as_mut_ptr()) };
        if accepted == 0 {
            return Ok(Outcome::Cancelled);
        }
        let mut count = 0i32;
        let mut native_error = no_error();
        // SAFETY: valid key, token and writable result.
        let counted = unsafe {
            sys::sdk_asl_count(
                self.asl.context.key(),
                self.token,
                &mut count,
                &mut native_error,
            )
        };
        if counted != 0 {
            return Err(refusal(native_error));
        }
        Ok(Outcome::Accepted(Selection {
            requester: self,
            count: usize::try_from(count).unwrap_or(0),
        }))
    }
}

impl Drop for FileRequester<'_, '_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = no_error();
        // SAFETY: the bridge forgets the requester first so it is freed once.
        let released =
            unsafe { sys::sdk_asl_release(self.asl.context.key(), token, &mut native_error) };
        if released == 0
            && let Ok(library) = self.asl.base()
        {
            // SAFETY: the library is open and the requester is ours alone.
            unsafe { sys::asl::free_asl_request(library, self.request) };
        }
    }
}

/// The paths a requester returned.
///
/// The selection borrows the requester, so it must be dropped before the
/// requester is shown again.
pub struct Selection<'r, 'a, 'ctx> {
    requester: &'r FileRequester<'a, 'ctx>,
    count: usize,
}

impl Selection<'_, '_, '_> {
    /// Returns how many paths were selected: at least one.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns whether no path was selected. A confirmed selection always has
    /// at least one path, so this is `false` for every selection returned.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns path `index` as an owned value: the selected drawer and file
    /// joined by the DOS path rules, or for a drawer selection the drawer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for an index past the end and
    /// [`Error::PathTooLong`] for a path over [`MAX_PATH_BYTES`].
    pub fn path(&self, index: usize) -> Result<AslPath, Error> {
        if index >= self.count {
            return Err(Error::Invalid);
        }
        let index = i32::try_from(index).map_err(|_| Error::Invalid)?;
        let mut path = AslPath {
            bytes: [0; MAX_PATH_BYTES],
            length: 0,
        };
        let mut native_error = no_error();
        // SAFETY: valid key, token and a writable buffer of the stated size.
        let built = unsafe {
            sys::sdk_asl_path(
                self.requester.asl.context.key(),
                self.requester.token,
                index,
                path.bytes.as_mut_ptr(),
                MAX_PATH_BYTES,
                &mut path.length,
                &mut native_error,
            )
        };
        if built != 0 {
            return Err(refusal(native_error));
        }
        Ok(path)
    }
}

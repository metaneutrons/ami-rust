#![no_std]
//! Task-affine Workbench applications for AROS, on `workbench.library`.
//!
//! [`Workbench`] opens `workbench.library` through [`aros::Library`] and owns
//! the reference. From it:
//!
//! - [`AppPort::new`] creates the message port Workbench sends application
//!   messages to. [`signal_mask`](AppPort::signal_mask) is its signal set for
//!   [`aros::wait_signals`], and [`next`](AppPort::next) returns the waiting
//!   [`AppMessage`]s;
//! - [`AppWindow::add`] makes an `aros-intuition` window accept icons dropped
//!   on it;
//! - [`AppIcon::add`] puts an icon on the Workbench desktop;
//! - [`AppMenuItem::add`] adds an item to the Workbench Tools menu;
//!
//! Every registration borrows the port and, for a window or an icon, the
//! window or disk object, so none of them can be freed while Workbench still
//! knows it. Dropping a registration removes it. The bridge owns the port and
//! the texts and removes registrations that are forgotten, returning pending
//! messages, when the program finishes.
//!
//! ```ignore
//! # use aros_intuition::{Intuition, WindowBuilder};
//! # use aros_workbench::{AppMessageKind, AppPort, AppWindow, Workbench};
//! let intuition = Intuition::open(context)?;
//! let window = WindowBuilder::new().title(b"Drop here").open(&intuition, None)?;
//! let workbench = Workbench::open(context)?;
//! let port = AppPort::new(&workbench)?;
//! let _drop_target = AppWindow::add(&port, &window, 1, 0)?;
//! aros::wait_signals(context, port.signal_mask())?;
//! while let Some(message) = port.next()? {
//!     if message.kind() == AppMessageKind::Window {
//!         let first = message.path(0)?;
//!         context.diagnostic(b"dropped bytes", first.len() as u64);
//!     }
//! }
//! ```
//!
//! # Sending a drop to one's own window
//!
//! `SendAppWindowMessage` (in `aros_sys::workbench`, on both ABIs) delivers
//! an application window message to the registered [`AppWindow`] of a window,
//! which is how a program tests its drop handling without a user dragging an
//! icon. It is **synchronous**: it returns only after the receiver has replied
//! to the message, and it holds the Workbench lock while it waits. Called from
//! the task that reads the [`AppPort`] it waits for itself and never returns,
//! so a second task has to make the call. For that reason this crate offers no
//! safe wrapper for it. [`AppPort::next`] replies to each message as it reads
//! it, and removing an [`AppWindow`], an [`AppIcon`] or an [`AppMenuItem`]
//! first replies to the messages already queued on the port, because the
//! removal needs the Workbench lock the sender is holding.
//!
//! # Limits
//!
//! A message carries at most [`MAX_MESSAGE_PATHS`] paths of at most
//! [`MAX_PATH_BYTES`] bytes; further ones are counted in
//! [`AppMessage::total_paths`] but not copied. An icon or menu item text is at
//! most 127 bytes, with no NUL byte.

use core::{
    ffi::{c_char, c_void},
    marker::PhantomData,
    mem, ptr,
};

use aros::{BytePath, Context, Library};
use aros_icon::DiskObject;
use aros_intuition::Window;
use aros_sys::{self as sys, SdkAppMessage, SdkError, wb};

const LIBRARY_NAME: &[u8] = b"workbench.library";
const MINIMUM_VERSION: u16 = 45;
const MAX_TEXT: usize = 127;
const KIND_WINDOW: i32 = 0;
const KIND_ICON: i32 = 1;
const KIND_MENU_ITEM: i32 = 2;

/// The most paths an [`AppMessage`] copies.
pub const MAX_MESSAGE_PATHS: usize = 8;
/// The longest path of an [`AppMessage`], in bytes.
pub const MAX_PATH_BYTES: usize = 256;

/// Why a Workbench operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The SDK refused the operation; see the [`aros::Error`].
    Aros(aros::Error),
    /// The native bridge ran out of memory.
    OutOfMemory,
    /// An argument is out of range, for example text that is too long or has a
    /// NUL byte, or a path index past the end.
    Invalid,
    /// Workbench refused the registration or the message, for example because
    /// it is not running or the window has no application window.
    Refused,
    /// A path of a message did not fit [`MAX_PATH_BYTES`].
    PathTooLong,
    /// A window operation failed; see the [`aros_intuition::Error`].
    Intuition(aros_intuition::Error),
    /// An icon operation failed; see the [`aros_icon::Error`].
    Icon(aros_icon::Error),
}

impl From<aros_intuition::Error> for Error {
    fn from(error: aros_intuition::Error) -> Self {
        Self::Intuition(error)
    }
}

impl From<aros_icon::Error> for Error {
    fn from(error: aros_icon::Error) -> Self {
        Self::Icon(error)
    }
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

/// An open `workbench.library`.
///
/// The handle is task-affine and borrows its [`Context`]. Ports and
/// registrations borrow it, so the library stays open while they exist.
pub struct Workbench<'ctx> {
    context: &'ctx Context,
    library: Library<'ctx>,
}

impl<'ctx> Workbench<'ctx> {
    /// Opens `workbench.library` (version 45 or newer).
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

/// The kind of an application message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppMessageKind {
    /// Icons were dropped on an [`AppWindow`].
    Window,
    /// An [`AppIcon`] was opened or had icons dropped on it.
    Icon,
    /// An [`AppMenuItem`] was chosen.
    MenuItem,
    /// A message type this crate does not decode, as its number.
    Other(u32),
}

/// A path of an application message, owned by the value.
#[derive(Clone, Copy)]
pub struct AppPath {
    bytes: [u8; MAX_PATH_BYTES],
    length: usize,
}

impl AppPath {
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
}

impl PartialEq for AppPath {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for AppPath {}

impl core::fmt::Debug for AppPath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AppPath(")?;
        for byte in self.as_bytes() {
            for escaped in core::ascii::escape_default(*byte) {
                core::fmt::Write::write_char(formatter, char::from(escaped))?;
            }
        }
        formatter.write_str(")")
    }
}

/// The message port Workbench sends application messages to.
///
/// The bridge owns the port. Dropping this value deletes it and returns any
/// messages still queued; a forgotten port is deleted when the program
/// finishes. The handle is task-affine and cannot be sent to another task.
pub struct AppPort<'w, 'ctx> {
    workbench: &'w Workbench<'ctx>,
    token: u64,
    port: *mut c_void,
    signal_mask: u32,
    _task_affine: PhantomData<*mut ()>,
}

impl<'w, 'ctx> AppPort<'w, 'ctx> {
    /// Creates the port.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the port cannot be created.
    pub fn new(workbench: &'w Workbench<'ctx>) -> Result<Self, Error> {
        let key = workbench.context.key();
        let mut native_error = no_error();
        // SAFETY: valid key and error record.
        let token = unsafe { sys::sdk_wb_port_new(key, &mut native_error) };
        if token == 0 {
            return Err(refusal(native_error));
        }
        // SAFETY: the record just created owns the port.
        let (port, signal_mask) = unsafe {
            (
                sys::sdk_wb_port_ptr(key, token),
                sys::sdk_wb_port_mask(key, token),
            )
        };
        Ok(Self {
            workbench,
            token,
            port,
            signal_mask,
            _task_affine: PhantomData,
        })
    }

    /// Returns the signal set of the port, for [`aros::wait_signals`] alone or
    /// together with other sources such as timers and window ports.
    pub const fn signal_mask(&self) -> u32 {
        self.signal_mask
    }

    /// Returns whether a message is waiting, without taking it.
    pub fn has_pending(&self) -> bool {
        // SAFETY: valid key and token.
        unsafe { sys::sdk_wb_port_pending(self.workbench.context.key(), self.token) != 0 }
    }

    /// Returns the next waiting message, or `None` if there is none.
    ///
    /// The message is taken from the port and returned to Workbench at once;
    /// the returned value owns a copy of its paths.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aros`] if the bridge no longer knows the port.
    pub fn next(&self) -> Result<Option<AppMessage>, Error> {
        let key = self.workbench.context.key();
        let mut raw = SdkAppMessage {
            kind: 0,
            class: 0,
            num_args: 0,
            total_args: 0,
            mouse_x: 0,
            mouse_y: 0,
            seconds: 0,
            micros: 0,
            id: 0,
            user_data: 0,
        };
        let mut native_error = no_error();
        // SAFETY: valid key, token and writable record.
        let result = unsafe { sys::sdk_wb_port_next(key, self.token, &mut raw, &mut native_error) };
        match result {
            1 => {}
            0 => return Ok(None),
            _ => return Err(refusal(native_error)),
        }
        let mut paths = [AppPath {
            bytes: [0; MAX_PATH_BYTES],
            length: 0,
        }; MAX_MESSAGE_PATHS];
        let copied = (raw.num_args as usize).min(MAX_MESSAGE_PATHS);
        for (index, path) in paths.iter_mut().enumerate().take(copied) {
            // SAFETY: valid key, token and a writable buffer of the stated size.
            let read = unsafe {
                sys::sdk_wb_path(
                    key,
                    self.token,
                    index as i32,
                    path.bytes.as_mut_ptr(),
                    MAX_PATH_BYTES,
                    &mut path.length,
                    &mut native_error,
                )
            };
            if read != 0 {
                return Err(refusal(native_error));
            }
        }
        Ok(Some(AppMessage { raw, paths }))
    }
}

impl Drop for AppPort<'_, '_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = no_error();
        // SAFETY: the bridge returns queued messages and deletes the port.
        let _ = unsafe {
            sys::sdk_wb_port_drop(self.workbench.context.key(), token, &mut native_error)
        };
    }
}

/// A message from Workbench: icons dropped on a window or an icon, or a menu
/// item chosen. It owns a copy of its paths.
#[derive(Clone, Copy)]
pub struct AppMessage {
    raw: SdkAppMessage,
    paths: [AppPath; MAX_MESSAGE_PATHS],
}

impl AppMessage {
    /// Returns what the message is about.
    pub fn kind(&self) -> AppMessageKind {
        match self.raw.kind {
            wb::AMTYPE_APP_WINDOW => AppMessageKind::Window,
            wb::AMTYPE_APP_ICON => AppMessageKind::Icon,
            wb::AMTYPE_APP_MENU_ITEM => AppMessageKind::MenuItem,
            other => AppMessageKind::Other(other),
        }
    }

    /// Returns the id given when the registration was added.
    pub const fn id(&self) -> u64 {
        self.raw.id
    }

    /// Returns the user data given when the registration was added.
    pub const fn user_data(&self) -> u64 {
        self.raw.user_data
    }

    /// Returns the message class (for an icon message, what was done to it).
    pub const fn class(&self) -> u32 {
        self.raw.class
    }

    /// Returns the pointer position of a drop, in window coordinates.
    pub const fn position(&self) -> (i16, i16) {
        (self.raw.mouse_x, self.raw.mouse_y)
    }

    /// Returns the time stamp of the message: seconds and microseconds.
    pub const fn time(&self) -> (u32, u32) {
        (self.raw.seconds, self.raw.micros)
    }

    /// Returns how many paths the message carries, including any that were
    /// not copied.
    pub fn total_paths(&self) -> usize {
        usize::try_from(self.raw.total_args).unwrap_or(0)
    }

    /// Returns how many paths were copied and can be read with
    /// [`path`](Self::path): at most [`MAX_MESSAGE_PATHS`].
    pub const fn copied_paths(&self) -> usize {
        self.raw.num_args as usize
    }

    /// Returns path `index`: the drawer and name Workbench gave, joined by the
    /// DOS path rules.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for an index past the copied paths.
    pub fn path(&self, index: usize) -> Result<AppPath, Error> {
        if index >= self.copied_paths() || index >= MAX_MESSAGE_PATHS {
            return Err(Error::Invalid);
        }
        Ok(self.paths[index])
    }
}

/// A NUL-terminated copy of a text, owned by the bridge once registered.
struct Registration<'p, 'w, 'ctx> {
    port: &'p AppPort<'w, 'ctx>,
    token: u64,
    kind: i32,
    _task_affine: PhantomData<*mut ()>,
}

impl<'p, 'w, 'ctx> Registration<'p, 'w, 'ctx> {
    /// Creates the bridge record holding `text` and returns it with the text's
    /// stable address; `attach` completes it once Workbench has the object.
    fn begin(
        port: &'p AppPort<'w, 'ctx>,
        kind: i32,
        text: &[u8],
    ) -> Result<(Self, *const c_char), Error> {
        if text.len() > MAX_TEXT || text.contains(&0) {
            return Err(Error::Invalid);
        }
        let key = port.workbench.context.key();
        let mut native_error = no_error();
        // SAFETY: the bridge copies the text into its own record.
        let token = unsafe {
            sys::sdk_wb_object_new(
                key,
                kind,
                port.token,
                text.as_ptr(),
                text.len(),
                &mut native_error,
            )
        };
        if token == 0 {
            return Err(refusal(native_error));
        }
        // SAFETY: the record just created owns the text.
        let text = unsafe { sys::sdk_wb_object_text(key, token) };
        Ok((
            Self {
                port,
                token,
                kind,
                _task_affine: PhantomData,
            },
            text,
        ))
    }

    fn attach(mut self, handle: *mut c_void) -> Result<Self, Error> {
        let key = self.port.workbench.context.key();
        let mut native_error = no_error();
        if handle.is_null() {
            // SAFETY: nothing else refers to the record.
            unsafe { sys::sdk_wb_object_cancel(key, self.token, &mut native_error) };
            self.token = 0;
            return Err(Error::Refused);
        }
        let base = self.port.workbench.base()?;
        // SAFETY: the bridge records the registration with the library base so
        // it can remove it if this handle is forgotten.
        let attached = unsafe {
            sys::sdk_wb_object_attach(key, self.token, base.cast(), handle, &mut native_error)
        };
        if attached != 0 {
            // SAFETY: the registration is ours and was just made; remove it
            // with the call of its kind, then forget the record.
            unsafe {
                match self.kind {
                    KIND_WINDOW => sys::workbench::remove_app_window(base, handle),
                    KIND_ICON => sys::workbench::remove_app_icon(base, handle),
                    _ => sys::workbench::remove_app_menu_item(base, handle),
                };
                sys::sdk_wb_object_cancel(key, self.token, &mut native_error);
            }
            self.token = 0;
            return Err(refusal(native_error));
        }
        Ok(self)
    }
}

impl Drop for Registration<'_, '_, '_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = no_error();
        // SAFETY: the bridge removes the registration it recorded and returns
        // the messages Workbench has already sent.
        let _ = unsafe {
            sys::sdk_wb_object_remove(self.port.workbench.context.key(), token, &mut native_error)
        };
    }
}

/// A window that accepts icons dropped on it.
///
/// It borrows the port and the window. Dropping it removes the registration.
pub struct AppWindow<'a, 'w, 'ctx> {
    _registration: Registration<'a, 'w, 'ctx>,
    _window: PhantomData<&'a ()>,
}

impl<'a, 'w, 'ctx> AppWindow<'a, 'w, 'ctx> {
    /// Registers `window` as an application window whose messages go to
    /// `port`, carrying `id` and `user_data`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Refused`] if Workbench does not accept the window.
    pub fn add(
        port: &'a AppPort<'w, 'ctx>,
        window: &'a Window<'_, '_>,
        id: usize,
        user_data: usize,
    ) -> Result<Self, Error> {
        let (registration, _) = Registration::begin(port, KIND_WINDOW, b"")?;
        let base = port.workbench.base()?;
        // SAFETY: the window and the port are open and outlive the
        // registration through the borrows.
        let handle = unsafe {
            sys::workbench::add_app_window_a(
                base,
                id,
                user_data,
                window.as_raw(),
                port.port,
                ptr::null_mut(),
            )
        };
        Ok(Self {
            _registration: registration.attach(handle)?,
            _window: PhantomData,
        })
    }
}

/// An icon on the Workbench desktop.
///
/// It borrows the port and the disk object. Dropping it removes the icon.
pub struct AppIcon<'a, 'w, 'ctx> {
    _registration: Registration<'a, 'w, 'ctx>,
    _icon: PhantomData<&'a ()>,
}

impl<'a, 'w, 'ctx> AppIcon<'a, 'w, 'ctx> {
    /// Puts `icon` on the Workbench desktop with the label `text` (at most 127
    /// bytes); its messages go to `port`, carrying `id` and `user_data`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a text that is too long or has a NUL byte
    /// and [`Error::Refused`] if Workbench does not accept the icon.
    pub fn add(
        port: &'a AppPort<'w, 'ctx>,
        icon: &'a DiskObject<'_, '_>,
        text: &[u8],
        id: usize,
        user_data: usize,
    ) -> Result<Self, Error> {
        let (registration, text) = Registration::begin(port, KIND_ICON, text)?;
        let base = port.workbench.base()?;
        // SAFETY: the text is kept by the bridge, the port and the disk object
        // outlive the registration through the borrows; there is no lock.
        let handle = unsafe {
            sys::workbench::add_app_icon_a(
                base,
                id,
                user_data,
                text,
                port.port,
                ptr::null_mut(),
                icon.as_raw(),
                ptr::null_mut(),
            )
        };
        Ok(Self {
            _registration: registration.attach(handle)?,
            _icon: PhantomData,
        })
    }
}

/// An item in the Workbench Tools menu.
///
/// It borrows the port. Dropping it removes the item.
pub struct AppMenuItem<'a, 'w, 'ctx> {
    _registration: Registration<'a, 'w, 'ctx>,
}

impl<'a, 'w, 'ctx> AppMenuItem<'a, 'w, 'ctx> {
    /// Adds a menu item labelled `text` (at most 127 bytes); choosing it sends
    /// a message to `port`, carrying `id` and `user_data`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a text that is too long or has a NUL byte
    /// and [`Error::Refused`] if Workbench does not accept the item.
    pub fn add(
        port: &'a AppPort<'w, 'ctx>,
        text: &[u8],
        id: usize,
        user_data: usize,
    ) -> Result<Self, Error> {
        let (registration, text) = Registration::begin(port, KIND_MENU_ITEM, text)?;
        let base = port.workbench.base()?;
        // SAFETY: the text is kept by the bridge and the port outlives the
        // registration through the borrow.
        let handle = unsafe {
            sys::workbench::add_app_menu_item_a(
                base,
                id,
                user_data,
                text,
                port.port,
                ptr::null_mut(),
            )
        };
        Ok(Self {
            _registration: registration.attach(handle)?,
        })
    }
}

#![no_std]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! Task-affine windows for AROS, on `intuition.library`.
//!
//! [`Intuition`] opens `intuition.library` through [`aros::Library`] and owns
//! the reference. From it:
//!
//! - [`PubScreen::lock`] locks a public screen (the default one, or one by
//!   name) for as long as the guard lives;
//! - [`WindowBuilder`] describes a window with a tag list that lives on the
//!   stack, and [`open`](WindowBuilder::open) creates the [`Window`];
//! - [`Window::next_event`] and [`Window::wait_event`] return typed
//!   [`Event`]s from the window's IDCMP port: close, keys, mouse buttons and
//!   movement, refresh, resize, activation;
//! - [`Window::signal_mask`] is the signal set of that port, for
//!   [`aros::wait_signals`] together with timers and other sources;
//! - [`Window::rastport`] lends the window's rastport to `aros-graphics` as a
//!   [`RastPortRef`] tied to the window.
//!
//! A window is closed when it is dropped. Pending messages are returned to
//! Intuition by the close. The title text lives in the native bridge, not in
//! the window value, so a window may be moved freely. A window or a screen lock
//! that is forgotten is released when the program finishes.
//!
//! ```ignore
//! # use aros_graphics::{Canvas, Graphics};
//! # use aros_intuition::{Event, Intuition, WindowBuilder};
//! let graphics = Graphics::open(context)?;
//! let intuition = Intuition::open(context)?;
//! let mut window = WindowBuilder::new()
//!     .title(b"Hello")
//!     .inner_size(200, 100)
//!     .open(&intuition, None)?;
//! {
//!     let mut canvas = window.rastport(&graphics);
//!     canvas.set_pen(1)?;
//!     canvas.fill_rect(10, 10, 90, 50)?;
//! }
//! while window.wait_event()? != Event::CloseWindow {}
//! ```
//!
//! # Limits
//!
//! A title is at most 127 bytes and a public screen name at most 63 bytes. The
//! builder sets at most 24 tags. Coordinates are 16-bit.

use core::{
    ffi::{c_char, c_void},
    marker::PhantomData,
    mem,
    ops::BitOr,
    ptr,
};

use aros::{BytePath, Context, Library};
use aros_graphics::{Graphics, RastPortRef};
use aros_sys::{self as sys, SdkError, SdkIntuiEvent, SdkWindowInfo, TagItem, idcmp, wa};

const LIBRARY_NAME: &[u8] = b"intuition.library";
const MINIMUM_VERSION: u16 = 39;
const MAX_TITLE_BYTES: usize = 127;
const MAX_SCREEN_NAME_BYTES: usize = 63;
const MAX_TAGS: usize = 24;

/// Why a window operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The SDK refused the operation; see the [`aros::Error`].
    Aros(aros::Error),
    /// The native bridge ran out of memory.
    OutOfMemory,
    /// An argument is out of range, for example a title that is too long or
    /// contains a NUL byte.
    Invalid,
    /// Intuition could not open the window, for example because the screen has
    /// no room for it or the requested size is impossible.
    OpenFailed,
    /// The named public screen does not exist.
    NoSuchScreen,
    /// A drawing operation failed; see the [`aros_graphics::Error`].
    Graphics(aros_graphics::Error),
}

impl From<aros_graphics::Error> for Error {
    fn from(error: aros_graphics::Error) -> Self {
        Self::Graphics(error)
    }
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

/// A set of IDCMP event classes a window asks Intuition to report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Idcmp(u32);

impl Idcmp {
    /// No events.
    pub const NONE: Self = Self(0);
    /// The window was resized.
    pub const NEW_SIZE: Self = Self(idcmp::NEW_SIZE);
    /// Part of the window must be redrawn.
    pub const REFRESH: Self = Self(idcmp::REFRESH_WINDOW);
    /// A mouse button was pressed or released.
    pub const MOUSE_BUTTONS: Self = Self(idcmp::MOUSE_BUTTONS);
    /// The mouse moved (also needs [`WindowBuilder::report_mouse`]).
    pub const MOUSE_MOVE: Self = Self(idcmp::MOUSE_MOVE);
    /// The close gadget was clicked.
    pub const CLOSE: Self = Self(idcmp::CLOSE_WINDOW);
    /// Raw key codes.
    pub const RAW_KEY: Self = Self(idcmp::RAW_KEY);
    /// Keys translated to characters by the keymap.
    pub const KEY: Self = Self(idcmp::VANILLA_KEY);
    /// The window became active.
    pub const ACTIVE: Self = Self(idcmp::ACTIVE_WINDOW);
    /// The window became inactive.
    pub const INACTIVE: Self = Self(idcmp::INACTIVE_WINDOW);
    /// Close, resize, refresh, mouse buttons, raw keys and characters.
    pub const DEFAULT: Self = Self(
        idcmp::CLOSE_WINDOW
            | idcmp::NEW_SIZE
            | idcmp::REFRESH_WINDOW
            | idcmp::MOUSE_BUTTONS
            | idcmp::RAW_KEY
            | idcmp::VANILLA_KEY,
    );

    /// Returns whether every class of `other` is in this set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for Idcmp {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Key qualifier bits of an event.
pub mod qualifier {
    /// Either shift key.
    pub const SHIFT: u16 = 0x0003;
    /// Caps lock is on.
    pub const CAPS_LOCK: u16 = 0x0004;
    /// The control key.
    pub const CONTROL: u16 = 0x0008;
    /// Either alt key.
    pub const ALT: u16 = 0x0030;
    /// Either command (Amiga) key.
    pub const COMMAND: u16 = 0x00c0;
    /// The key is auto-repeating.
    pub const REPEAT: u16 = 0x0200;
}

/// A mouse button.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MouseButton {
    /// The select button (usually the left one).
    Select,
    /// The menu button (usually the right one).
    Menu,
    /// The middle button.
    Middle,
}

/// An event from a window's IDCMP port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// The close gadget was clicked. The window is still open; drop it to
    /// close it.
    CloseWindow,
    /// The window changed size; read [`Window::info`].
    NewSize,
    /// Part of the window must be redrawn: call [`Window::begin_refresh`],
    /// draw, and drop the guard.
    Refresh,
    /// A mouse button changed state. `x` and `y` are window coordinates.
    MouseButton {
        /// Which button.
        button: MouseButton,
        /// Whether it went down.
        pressed: bool,
        /// Pointer x position relative to the window's left edge.
        x: i16,
        /// Pointer y position relative to the window's top edge.
        y: i16,
        /// Qualifier bits, see [`qualifier`].
        qualifier: u16,
    },
    /// The pointer moved (needs [`WindowBuilder::report_mouse`]).
    MouseMove {
        /// Pointer x position relative to the window's left edge.
        x: i16,
        /// Pointer y position relative to the window's top edge.
        y: i16,
    },
    /// A key changed state, as a raw key code.
    RawKey {
        /// The key code without the release bit.
        code: u8,
        /// Whether the key went down.
        pressed: bool,
        /// Qualifier bits, see [`qualifier`].
        qualifier: u16,
    },
    /// A key produced a character through the keymap.
    Key {
        /// The character code (ISO 8859-1).
        character: u8,
        /// Qualifier bits, see [`qualifier`].
        qualifier: u16,
    },
    /// The window became active.
    Activated,
    /// The window became inactive.
    Deactivated,
    /// An event class this crate does not decode, as its IDCMP bit.
    Other(u32),
}

impl Event {
    fn decode(raw: SdkIntuiEvent) -> Self {
        match raw.class {
            idcmp::CLOSE_WINDOW => Self::CloseWindow,
            idcmp::NEW_SIZE => Self::NewSize,
            idcmp::REFRESH_WINDOW => Self::Refresh,
            idcmp::ACTIVE_WINDOW => Self::Activated,
            idcmp::INACTIVE_WINDOW => Self::Deactivated,
            idcmp::MOUSE_MOVE => Self::MouseMove { x: raw.x, y: raw.y },
            idcmp::MOUSE_BUTTONS => {
                let (button, pressed) = match raw.code {
                    idcmp::SELECT_DOWN => (MouseButton::Select, true),
                    idcmp::SELECT_UP => (MouseButton::Select, false),
                    idcmp::MENU_DOWN => (MouseButton::Menu, true),
                    idcmp::MENU_UP => (MouseButton::Menu, false),
                    idcmp::MIDDLE_DOWN => (MouseButton::Middle, true),
                    idcmp::MIDDLE_UP => (MouseButton::Middle, false),
                    _ => return Self::Other(raw.class),
                };
                Self::MouseButton {
                    button,
                    pressed,
                    x: raw.x,
                    y: raw.y,
                    qualifier: raw.qualifier,
                }
            }
            idcmp::RAW_KEY => Self::RawKey {
                code: (raw.code & 0x7f) as u8,
                pressed: raw.code & 0x80 == 0,
                qualifier: raw.qualifier,
            },
            idcmp::VANILLA_KEY => Self::Key {
                character: (raw.code & 0xff) as u8,
                qualifier: raw.qualifier,
            },
            other => Self::Other(other),
        }
    }
}

/// An open `intuition.library`.
///
/// The handle is task-affine and borrows its [`Context`]. Screens and windows
/// borrow it, so the library stays open while they exist.
///
/// ```compile_fail
/// use aros_intuition::{Intuition, WindowBuilder};
///
/// fn escape(context: &aros::Context) {
///     let window;
///     {
///         let intuition = Intuition::open(context).unwrap();
///         window = WindowBuilder::new().open(&intuition, None).unwrap();
///     }
///     // The library is closed again, so the window cannot be used.
///     let _ = window.info();
/// }
/// ```
pub struct Intuition<'ctx> {
    context: &'ctx Context,
    library: Library<'ctx>,
}

impl<'ctx> Intuition<'ctx> {
    /// Opens `intuition.library` (version 39 or newer).
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

/// A locked public screen.
///
/// While the guard lives the screen cannot close. Dropping it unlocks the
/// screen; one that is forgotten is unlocked when the program finishes.
pub struct PubScreen<'i, 'ctx> {
    intuition: &'i Intuition<'ctx>,
    token: u64,
    screen: *mut c_void,
    width: u16,
    height: u16,
    _task_affine: PhantomData<*mut ()>,
}

impl<'i, 'ctx> PubScreen<'i, 'ctx> {
    /// Locks the public screen called `name`, or the default public screen
    /// (usually the Workbench screen) for `None`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a name of more than 63 bytes or one with
    /// a NUL byte, and [`Error::NoSuchScreen`] if no such screen exists.
    pub fn lock(intuition: &'i Intuition<'ctx>, name: Option<&[u8]>) -> Result<Self, Error> {
        let mut buffer = [0u8; MAX_SCREEN_NAME_BYTES + 1];
        let pointer: *const c_char = match name {
            None => ptr::null(),
            Some(name) => {
                if name.len() > MAX_SCREEN_NAME_BYTES || name.contains(&0) {
                    return Err(Error::Invalid);
                }
                buffer[..name.len()].copy_from_slice(name);
                buffer.as_ptr().cast()
            }
        };
        let library = intuition.base()?;
        // SAFETY: `pointer` is null or a NUL-terminated name that outlives the
        // call; the library base is open.
        let screen = unsafe { sys::intuition::lock_pub_screen(library, pointer) };
        if screen.is_null() {
            return Err(Error::NoSuchScreen);
        }
        let key = intuition.context.key();
        let mut native_error = no_error();
        // SAFETY: the bridge records the screen with the library base so it
        // can unlock the screen if this guard is forgotten.
        let token = unsafe {
            sys::sdk_intui_screen_register(key, library.cast(), screen, &mut native_error)
        };
        if token == 0 {
            // SAFETY: the lock was just taken and is released again.
            unsafe { sys::intuition::unlock_pub_screen(library, ptr::null_mut(), screen) };
            return Err(refusal(native_error));
        }
        let (mut width, mut height) = (0i32, 0i32);
        // SAFETY: valid key, token and writable results.
        unsafe {
            sys::sdk_intui_screen_size(key, token, &mut width, &mut height, &mut native_error)
        };
        Ok(Self {
            intuition,
            token,
            screen,
            width: width.clamp(0, i32::from(u16::MAX)) as u16,
            height: height.clamp(0, i32::from(u16::MAX)) as u16,
            _task_affine: PhantomData,
        })
    }

    /// Returns the screen width in pixels.
    pub const fn width(&self) -> u16 {
        self.width
    }

    /// Returns the screen height in pixels.
    pub const fn height(&self) -> u16 {
        self.height
    }
}

impl Drop for PubScreen<'_, '_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = no_error();
        // SAFETY: the bridge forgets the lock first so it is released once.
        let released = unsafe {
            sys::sdk_intui_screen_release(self.intuition.context.key(), token, &mut native_error)
        };
        if released == 0
            && let Ok(library) = self.intuition.base()
        {
            // SAFETY: the lock is ours alone and the library is open.
            unsafe { sys::intuition::unlock_pub_screen(library, ptr::null_mut(), self.screen) };
        }
    }
}

/// Describes a window to open.
///
/// The defaults are a 200 by 100 window at the default position with a drag
/// bar, depth gadget and close gadget, activated, with smart refresh and the
/// [`Idcmp::DEFAULT`] events. All text is copied by the native bridge.
#[derive(Clone, Copy, Debug)]
pub struct WindowBuilder<'t> {
    title: &'t [u8],
    position: Option<(i16, i16)>,
    inner_size: (u16, u16),
    limits: Option<(u16, u16, u16, u16)>,
    close_gadget: bool,
    drag_bar: bool,
    depth_gadget: bool,
    size_gadget: bool,
    activate: bool,
    smart_refresh: bool,
    report_mouse: bool,
    borderless: bool,
    idcmp: Idcmp,
}

impl Default for WindowBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'t> WindowBuilder<'t> {
    /// Creates a builder with the defaults.
    pub const fn new() -> Self {
        Self {
            title: b"",
            position: None,
            inner_size: (200, 100),
            limits: None,
            close_gadget: true,
            drag_bar: true,
            depth_gadget: true,
            size_gadget: false,
            activate: true,
            smart_refresh: true,
            report_mouse: false,
            borderless: false,
            idcmp: Idcmp::DEFAULT,
        }
    }

    /// Sets the window title (at most 127 bytes, no NUL).
    #[must_use]
    pub const fn title(mut self, title: &'t [u8]) -> Self {
        self.title = title;
        self
    }

    /// Sets the position of the window's top left corner.
    #[must_use]
    pub const fn position(mut self, left: i16, top: i16) -> Self {
        self.position = Some((left, top));
        self
    }

    /// Sets the size of the drawable area inside the borders.
    #[must_use]
    pub const fn inner_size(mut self, width: u16, height: u16) -> Self {
        self.inner_size = (width, height);
        self
    }

    /// Sets the smallest and largest outer size a user can resize to, and
    /// turns on the size gadget.
    #[must_use]
    pub const fn limits(
        mut self,
        min_width: u16,
        min_height: u16,
        max_width: u16,
        max_height: u16,
    ) -> Self {
        self.limits = Some((min_width, min_height, max_width, max_height));
        self.size_gadget = true;
        self
    }

    /// Turns the close gadget on or off.
    #[must_use]
    pub const fn close_gadget(mut self, on: bool) -> Self {
        self.close_gadget = on;
        self
    }

    /// Turns the drag bar on or off.
    #[must_use]
    pub const fn drag_bar(mut self, on: bool) -> Self {
        self.drag_bar = on;
        self
    }

    /// Turns the depth gadget on or off.
    #[must_use]
    pub const fn depth_gadget(mut self, on: bool) -> Self {
        self.depth_gadget = on;
        self
    }

    /// Turns the size gadget on or off.
    #[must_use]
    pub const fn size_gadget(mut self, on: bool) -> Self {
        self.size_gadget = on;
        self
    }

    /// Activates the window when it opens.
    #[must_use]
    pub const fn activate(mut self, on: bool) -> Self {
        self.activate = on;
        self
    }

    /// Chooses smart refresh (the system keeps the hidden parts) or simple
    /// refresh (the program redraws on [`Event::Refresh`]).
    #[must_use]
    pub const fn smart_refresh(mut self, on: bool) -> Self {
        self.smart_refresh = on;
        self
    }

    /// Reports every pointer movement as [`Event::MouseMove`].
    #[must_use]
    pub const fn report_mouse(mut self, on: bool) -> Self {
        self.report_mouse = on;
        self
    }

    /// Opens the window without borders or gadgets.
    #[must_use]
    pub const fn borderless(mut self, on: bool) -> Self {
        self.borderless = on;
        self
    }

    /// Sets the event classes the window reports.
    #[must_use]
    pub const fn idcmp(mut self, idcmp: Idcmp) -> Self {
        self.idcmp = idcmp;
        self
    }

    /// Opens the window on `screen`, or on the default public screen for
    /// `None`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a title that is too long or has a NUL
    /// byte, [`Error::OutOfMemory`] if the bridge cannot record the window and
    /// [`Error::OpenFailed`] if Intuition refuses the window.
    pub fn open<'i, 'ctx>(
        &self,
        intuition: &'i Intuition<'ctx>,
        screen: Option<&PubScreen<'i, 'ctx>>,
    ) -> Result<Window<'i, 'ctx>, Error> {
        if self.title.len() > MAX_TITLE_BYTES || self.title.contains(&0) {
            return Err(Error::Invalid);
        }
        let library = intuition.base()?;
        let key = intuition.context.key();
        let mut native_error = no_error();
        // SAFETY: the bridge copies the title into its own record.
        let token = unsafe {
            sys::sdk_intui_title_new(
                key,
                self.title.as_ptr(),
                self.title.len(),
                &mut native_error,
            )
        };
        if token == 0 {
            return Err(refusal(native_error));
        }
        // SAFETY: the record just created owns the title text.
        let title = unsafe { sys::sdk_intui_title_ptr(key, token) };

        let mut tags = [TagItem::new(sys::TAG_DONE, 0); MAX_TAGS + 1];
        let mut count = 0;
        let mut push = |tag: u32, data: usize| {
            tags[count] = TagItem::new(tag, data);
            count += 1;
        };
        push(wa::TITLE, title as usize);
        push(wa::INNER_WIDTH, usize::from(self.inner_size.0));
        push(wa::INNER_HEIGHT, usize::from(self.inner_size.1));
        push(
            wa::IDCMP,
            (self.idcmp.0
                | if self.report_mouse {
                    idcmp::MOUSE_MOVE
                } else {
                    0
                }) as usize,
        );
        if let Some((left, top)) = self.position {
            push(wa::LEFT, left as isize as usize);
            push(wa::TOP, top as isize as usize);
        }
        if let Some((min_width, min_height, max_width, max_height)) = self.limits {
            push(wa::MIN_WIDTH, usize::from(min_width));
            push(wa::MIN_HEIGHT, usize::from(min_height));
            push(wa::MAX_WIDTH, usize::from(max_width));
            push(wa::MAX_HEIGHT, usize::from(max_height));
        }
        push(wa::CLOSE_GADGET, usize::from(self.close_gadget));
        push(wa::DRAG_BAR, usize::from(self.drag_bar));
        push(wa::DEPTH_GADGET, usize::from(self.depth_gadget));
        push(wa::SIZE_GADGET, usize::from(self.size_gadget));
        push(wa::ACTIVATE, usize::from(self.activate));
        push(wa::REPORT_MOUSE, usize::from(self.report_mouse));
        push(wa::BORDERLESS, usize::from(self.borderless));
        push(
            if self.smart_refresh {
                wa::SMART_REFRESH
            } else {
                wa::SIMPLE_REFRESH
            },
            1,
        );
        if let Some(screen) = screen {
            push(wa::PUB_SCREEN, screen.screen as usize);
        }

        // SAFETY: the tag list is terminated and lives through the call; the
        // title text and the screen lock outlive it.
        let window = unsafe {
            sys::intuition::open_window_tag_list(library, ptr::null_mut(), tags.as_mut_ptr())
        };
        if window.is_null() {
            // SAFETY: nothing else refers to the title record.
            unsafe { sys::sdk_intui_window_cancel(key, token, &mut native_error) };
            return Err(Error::OpenFailed);
        }
        // SAFETY: the bridge records the window with the library base so it
        // can close the window if this handle is forgotten.
        let attached = unsafe {
            sys::sdk_intui_window_attach(key, token, library.cast(), window, &mut native_error)
        };
        if attached != 0 {
            // SAFETY: the window is ours and was just opened.
            unsafe { sys::intuition::close_window(library, window) };
            // SAFETY: nothing else refers to the title record.
            unsafe { sys::sdk_intui_window_cancel(key, token, &mut native_error) };
            return Err(refusal(native_error));
        }
        let mut info = empty_info();
        // SAFETY: valid key, token and record.
        let read = unsafe { sys::sdk_intui_window_info(key, token, &mut info, &mut native_error) };
        if read != 0 {
            // SAFETY: the bridge closes the window it records.
            unsafe { sys::sdk_intui_window_close(key, token, &mut native_error) };
            return Err(refusal(native_error));
        }
        Ok(Window {
            intuition,
            token,
            window,
            rastport: info.rastport,
            signal_mask: info.signal_mask,
            _task_affine: PhantomData,
        })
    }
}

fn empty_info() -> SdkWindowInfo {
    SdkWindowInfo {
        left: 0,
        top: 0,
        width: 0,
        height: 0,
        border_left: 0,
        border_top: 0,
        border_right: 0,
        border_bottom: 0,
        mouse_x: 0,
        mouse_y: 0,
        screen_width: 0,
        screen_height: 0,
        signal_mask: 0,
        rastport: ptr::null_mut(),
    }
}

/// The geometry of a window, in pixels, as Intuition reports it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowInfo {
    /// Left edge of the window on its screen.
    pub left: i16,
    /// Top edge of the window on its screen.
    pub top: i16,
    /// Outer width including borders.
    pub width: u16,
    /// Outer height including borders.
    pub height: u16,
    /// Width of the left border.
    pub border_left: u16,
    /// Height of the top border (the title bar).
    pub border_top: u16,
    /// Width of the right border.
    pub border_right: u16,
    /// Height of the bottom border.
    pub border_bottom: u16,
    /// Width of the drawable area inside the borders.
    pub inner_width: u16,
    /// Height of the drawable area inside the borders.
    pub inner_height: u16,
    /// Pointer x position relative to the window's left edge.
    pub mouse_x: i16,
    /// Pointer y position relative to the window's top edge.
    pub mouse_y: i16,
    /// Width of the screen the window is on.
    pub screen_width: u16,
    /// Height of the screen the window is on.
    pub screen_height: u16,
}

/// An open window.
///
/// Dropping the window closes it. The handle is task-affine, borrows its
/// [`Intuition`] and cannot be sent to another task.
pub struct Window<'i, 'ctx> {
    intuition: &'i Intuition<'ctx>,
    token: u64,
    window: *mut c_void,
    rastport: *mut c_void,
    signal_mask: u32,
    _task_affine: PhantomData<*mut ()>,
}

impl<'i, 'ctx> Window<'i, 'ctx> {
    fn key(&self) -> u64 {
        self.intuition.context.key()
    }

    fn library(&self) -> Result<*mut sys::Library, Error> {
        self.intuition.base()
    }

    /// Returns the signal set of the window's IDCMP port.
    ///
    /// Pass it, alone or combined with the masks of timers and other sources,
    /// to [`aros::wait_signals`], then read events with
    /// [`next_event`](Self::next_event) until it returns `None`.
    pub const fn signal_mask(&self) -> u32 {
        self.signal_mask
    }

    /// Returns the next waiting event, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aros`] if the bridge no longer knows the window.
    pub fn next_event(&mut self) -> Result<Option<Event>, Error> {
        let mut raw = SdkIntuiEvent {
            class: 0,
            code: 0,
            qualifier: 0,
            x: 0,
            y: 0,
            seconds: 0,
            micros: 0,
        };
        let mut native_error = no_error();
        // SAFETY: valid key, token and writable event record.
        let result = unsafe {
            sys::sdk_intui_next_event(self.key(), self.token, &mut raw, &mut native_error)
        };
        match result {
            1 => Ok(Some(Event::decode(raw))),
            0 => Ok(None),
            _ => Err(refusal(native_error)),
        }
    }

    /// Waits until an event arrives and returns it.
    ///
    /// This blocks on the window's port only. To wait for other signals as
    /// well, use [`signal_mask`](Self::signal_mask) with
    /// [`aros::wait_signals`] and [`next_event`](Self::next_event).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aros`] if the wait or the read fails.
    pub fn wait_event(&mut self) -> Result<Event, Error> {
        loop {
            if let Some(event) = self.next_event()? {
                return Ok(event);
            }
            aros::wait_signals(self.intuition.context, self.signal_mask)?;
        }
    }

    /// Returns the current geometry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Aros`] if the bridge no longer knows the window.
    pub fn info(&self) -> Result<WindowInfo, Error> {
        let mut info = empty_info();
        let mut native_error = no_error();
        // SAFETY: valid key, token and writable record.
        let read = unsafe {
            sys::sdk_intui_window_info(self.key(), self.token, &mut info, &mut native_error)
        };
        if read != 0 {
            return Err(refusal(native_error));
        }
        let unsigned = |value: i32| value.clamp(0, i32::from(u16::MAX)) as u16;
        let signed = |value: i32| value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
        let width = unsigned(info.width);
        let height = unsigned(info.height);
        let (left, right) = (unsigned(info.border_left), unsigned(info.border_right));
        let (top, bottom) = (unsigned(info.border_top), unsigned(info.border_bottom));
        Ok(WindowInfo {
            left: signed(info.left),
            top: signed(info.top),
            width,
            height,
            border_left: left,
            border_top: top,
            border_right: right,
            border_bottom: bottom,
            inner_width: width.saturating_sub(left + right),
            inner_height: height.saturating_sub(top + bottom),
            mouse_x: signed(info.mouse_x),
            mouse_y: signed(info.mouse_y),
            screen_width: unsigned(info.screen_width),
            screen_height: unsigned(info.screen_height),
        })
    }

    /// Lends the window's rastport for drawing with `aros-graphics`.
    ///
    /// The result is tied to the window and to `graphics`, so it cannot
    /// outlive either. Drawing is clipped to the window by Intuition.
    pub fn rastport<'a>(&'a self, graphics: &'a Graphics<'ctx>) -> RastPortRef<'a, 'ctx> {
        // SAFETY: the rastport belongs to this open window and stays valid
        // for as long as the window does; the result borrows the window.
        unsafe { RastPortRef::borrow(graphics, self.rastport, self) }
    }

    /// Replaces the window title (at most 127 bytes, no NUL).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a title that is too long or has a NUL
    /// byte.
    pub fn set_title(&mut self, title: &[u8]) -> Result<(), Error> {
        if title.len() > MAX_TITLE_BYTES || title.contains(&0) {
            return Err(Error::Invalid);
        }
        let mut native_error = no_error();
        // SAFETY: the bridge copies the text into the record Intuition reads.
        let set = unsafe {
            sys::sdk_intui_window_set_title(
                self.key(),
                self.token,
                title.as_ptr(),
                title.len(),
                &mut native_error,
            )
        };
        if set != 0 {
            return Err(refusal(native_error));
        }
        // SAFETY: the record owns the text for the window's lifetime; a null
        // screen title leaves the screen title unchanged (-1).
        unsafe {
            let text = sys::sdk_intui_title_ptr(self.key(), self.token);
            sys::intuition::set_window_titles(
                self.library()?,
                self.window,
                text,
                usize::MAX as *const c_char,
            );
        }
        Ok(())
    }

    /// Makes the window the active one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    pub fn activate(&self) -> Result<(), Error> {
        // SAFETY: valid library base and window.
        unsafe { sys::intuition::activate_window(self.library()?, self.window) };
        Ok(())
    }

    /// Moves the window in front of the others on its screen.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    pub fn to_front(&self) -> Result<(), Error> {
        // SAFETY: valid library base and window.
        unsafe { sys::intuition::window_to_front(self.library()?, self.window) };
        Ok(())
    }

    /// Moves the window behind the others on its screen.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    pub fn to_back(&self) -> Result<(), Error> {
        // SAFETY: valid library base and window.
        unsafe { sys::intuition::window_to_back(self.library()?, self.window) };
        Ok(())
    }

    /// Moves the window by `(dx, dy)` pixels. The move takes effect when
    /// Intuition processes it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    pub fn move_by(&self, dx: i16, dy: i16) -> Result<(), Error> {
        // SAFETY: valid library base and window.
        unsafe {
            sys::intuition::move_window(self.library()?, self.window, i32::from(dx), i32::from(dy))
        };
        Ok(())
    }

    /// Changes the outer size by `(dx, dy)` pixels. The change takes effect
    /// when Intuition processes it and is reported as [`Event::NewSize`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    pub fn resize_by(&self, dx: i16, dy: i16) -> Result<(), Error> {
        // SAFETY: valid library base and window.
        unsafe {
            sys::intuition::size_window(self.library()?, self.window, i32::from(dx), i32::from(dy))
        };
        Ok(())
    }

    /// Moves and resizes the window in one step to the outer box.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    pub fn set_box(&self, left: i16, top: i16, width: u16, height: u16) -> Result<(), Error> {
        // SAFETY: valid library base and window.
        unsafe {
            sys::intuition::change_window_box(
                self.library()?,
                self.window,
                i32::from(left),
                i32::from(top),
                i32::from(width),
                i32::from(height),
            )
        };
        Ok(())
    }

    /// Starts redrawing the damaged part of a simple-refresh window after
    /// [`Event::Refresh`]. Drawing until the guard is dropped is clipped to
    /// the damage; dropping the guard completes the refresh.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    pub fn begin_refresh(&self) -> Result<Refresh<'_, 'i, 'ctx>, Error> {
        let library = self.library()?;
        // SAFETY: valid library base and window.
        unsafe { sys::intuition::begin_refresh(library, self.window) };
        Ok(Refresh { window: self })
    }

    /// Closes the window now. Dropping it does the same.
    pub fn close(self) {}
}

impl Drop for Window<'_, '_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = no_error();
        // SAFETY: the bridge closes the window it recorded and forgets the
        // record; Intuition returns any pending messages.
        let _ = unsafe { sys::sdk_intui_window_close(self.key(), token, &mut native_error) };
    }
}

/// A refresh in progress, started by [`Window::begin_refresh`].
///
/// Dropping the guard completes the refresh.
pub struct Refresh<'w, 'i, 'ctx> {
    window: &'w Window<'i, 'ctx>,
}

impl Drop for Refresh<'_, '_, '_> {
    fn drop(&mut self) {
        if let Ok(library) = self.window.library() {
            // SAFETY: valid library base; the refresh was begun on this window.
            unsafe { sys::intuition::end_refresh(library, self.window.window, 1) };
        }
    }
}

#![no_std]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! Task-affine bitmaps and drawing for AROS, on `graphics.library`.
//!
//! [`Graphics`] opens `graphics.library` through [`aros::Library`] and owns the
//! reference. From it:
//!
//! - [`Graphics::bitmap`] allocates an off-screen [`BitMap`] of one to eight
//!   bits of depth, so each pixel is a pen number;
//! - [`BitMap::rastport`] creates the [`RastPort`] that draws into a bitmap;
//! - [`RastPortRef`] is the borrowed form for a rastport that another object
//!   owns, such as a window's. Its lifetime is tied to that owner, so it cannot
//!   outlive it.
//!
//! Drawing is done through [`Canvas`], implemented by both: pens and drawing
//! modes, [`move_to`](Canvas::move_to) and [`line_to`](Canvas::line_to),
//! [`fill_rect`](Canvas::fill_rect), [`ellipse`](Canvas::ellipse),
//! [`polygon`](Canvas::polygon), [`text`](Canvas::text) and
//! [`text_length`](Canvas::text_length), [`read_pixel`](Canvas::read_pixel),
//! and blits between bitmaps ([`BitMap::blit`], [`Canvas::blit_from`]).
//! [`RastPort::fill_polygon`] fills a polygon and needs the buffers only a
//! bitmap's rastport has.
//!
//! The crate allocates nothing on the Rust heap and behaves the same on ABI-v1
//! and ABI-v11. The native bridge owns the rastport memory and the fill buffers
//! and tracks every bitmap, so a forgotten object is released when the program
//! ends.
//!
//! ```ignore
//! # use aros_graphics::{Canvas, Graphics};
//! let graphics = Graphics::open(context)?;
//! let mut bitmap = graphics.bitmap(64, 48, 8)?;
//! let mut rastport = bitmap.rastport()?;
//! rastport.set_pen(1)?;
//! rastport.fill_rect(4, 4, 30, 20)?;
//! assert_eq!(rastport.read_pixel(10, 10)?, Some(1));
//! ```
//!
//! # Limits
//!
//! A bitmap is at most 32,767 by 32,767 pixels with a depth of 1 to 8. A
//! polygon has at most [`MAX_POLYGON_POINTS`] points and text at most 65,535
//! bytes per call. Coordinates are 16-bit, as the library takes them.

use core::{ffi::c_void, marker::PhantomData, mem};

use aros::{BytePath, Context, Library};
use aros_sys::{self as sys, SdkError};

const LIBRARY_NAME: &[u8] = b"graphics.library";
const MINIMUM_VERSION: u16 = 39;
const BMF_CLEAR: u32 = 1;
const MINTERM_COPY: u32 = 0xc0;

/// The most points a polygon can have.
pub const MAX_POLYGON_POINTS: usize = 256;
/// The largest bitmap side in pixels.
pub const MAX_BITMAP_SIDE: u16 = 32_767;
/// The most bytes [`Canvas::text`] draws in one call.
pub const MAX_TEXT_BYTES: usize = 65_535;

/// Why a drawing operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The SDK refused the operation; see the [`aros::Error`].
    Aros(aros::Error),
    /// The library or the native bridge ran out of memory.
    OutOfMemory,
    /// An argument is out of range, for example a bitmap with a zero side or a
    /// depth above eight, or a polygon with too many points.
    Invalid,
    /// The library reported failure, for example a polygon with too many
    /// vertices for its fill buffer.
    Failed,
}

impl From<aros::Error> for Error {
    fn from(error: aros::Error) -> Self {
        Self::Aros(error)
    }
}

/// How a drawing operation combines the pen with the pixels already there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DrawMode {
    /// `JAM1`: draw in the foreground pen only.
    Jam1 = 0,
    /// `JAM2`: draw in the foreground pen and fill the gaps with the
    /// background pen.
    Jam2 = 1,
    /// `COMPLEMENT`: invert the pixels.
    Complement = 2,
    /// `INVERSVID`: swap the roles of the two pens.
    InverseVideo = 4,
}

fn base(library: &Library<'_>) -> Result<*mut sys::Library, Error> {
    // SAFETY: the pointer is this open library's base, used immediately by the
    // owner task for its own library API.
    match unsafe { library.raw_base() } {
        Some(base) => Ok(base.cast()),
        None => Err(Error::Invalid),
    }
}

/// An open `graphics.library`.
///
/// The handle is task-affine and borrows its [`Context`]. Bitmaps and
/// rastports borrow it, so the library stays open while they exist.
pub struct Graphics<'ctx> {
    context: &'ctx Context,
    library: Library<'ctx>,
}

impl<'ctx> Graphics<'ctx> {
    /// Opens `graphics.library` (version 39 or newer).
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
        base(&self.library)
    }

    /// Allocates an off-screen bitmap of `width` by `height` pixels and
    /// `depth` bits (1 to 8), cleared to pen 0.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for a side that is zero or above
    /// [`MAX_BITMAP_SIDE`] or a depth outside 1 to 8, and
    /// [`Error::OutOfMemory`] if the library cannot allocate it.
    pub fn bitmap(&self, width: u16, height: u16, depth: u8) -> Result<BitMap<'_, 'ctx>, Error> {
        if width == 0 || height == 0 || width > MAX_BITMAP_SIDE || height > MAX_BITMAP_SIDE {
            return Err(Error::Invalid);
        }
        if !(1..=8).contains(&depth) {
            return Err(Error::Invalid);
        }
        let library = self.base()?;
        // SAFETY: `library` is the open graphics library base.
        let bitmap = unsafe {
            sys::graphics::alloc_bit_map(
                library,
                width,
                height,
                u32::from(depth),
                BMF_CLEAR,
                core::ptr::null_mut(),
            )
        };
        if bitmap.is_null() {
            return Err(Error::OutOfMemory);
        }
        let mut native_error = SdkError { kind: 0, native: 0 };
        // SAFETY: the bridge records the library base and the bitmap so it can
        // free the bitmap if this handle is forgotten.
        let token = unsafe {
            sys::sdk_gfx_bitmap_register(
                self.context.key(),
                library.cast(),
                bitmap,
                &mut native_error,
            )
        };
        if token == 0 {
            // SAFETY: the bitmap is still ours and was just allocated.
            unsafe { sys::graphics::free_bit_map(library, bitmap) };
            return Err(Error::Aros(aros::Error {
                kind: aros::ErrorKind::Native,
                native: native_error.native,
                operation: aros::Operation::LibraryOpen,
            }));
        }
        Ok(BitMap {
            graphics: self,
            bitmap,
            token,
            width,
            height,
            depth,
            _task_affine: PhantomData,
        })
    }
}

/// An off-screen bitmap.
///
/// Each pixel is a pen number of [`depth`](Self::depth) bits. Draw into it
/// through [`rastport`](Self::rastport). Dropping the bitmap waits for the
/// blitter and frees it; a forgotten bitmap is freed when the program ends.
pub struct BitMap<'g, 'ctx> {
    graphics: &'g Graphics<'ctx>,
    bitmap: *mut c_void,
    token: u64,
    width: u16,
    height: u16,
    depth: u8,
    _task_affine: PhantomData<*mut ()>,
}

impl<'g, 'ctx> BitMap<'g, 'ctx> {
    /// Returns the width in pixels.
    pub const fn width(&self) -> u16 {
        self.width
    }

    /// Returns the height in pixels.
    pub const fn height(&self) -> u16 {
        self.height
    }

    /// Returns the depth in bits.
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// Creates the rastport that draws into this bitmap.
    ///
    /// The rastport borrows the bitmap mutably, so the bitmap cannot be freed
    /// or used by a blit while the rastport exists.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] or [`Error::Aros`] if the rastport cannot
    /// be created.
    pub fn rastport<'b>(&'b mut self) -> Result<RastPort<'b, 'g, 'ctx>, Error> {
        let library = self.graphics.base()?;
        let context = self.graphics.context;
        let mut native_error = SdkError { kind: 0, native: 0 };
        // SAFETY: valid context key and error record.
        let token = unsafe { sys::sdk_gfx_rastport_new(context.key(), &mut native_error) };
        if token == 0 {
            return Err(refusal(native_error));
        }
        // SAFETY: the pointer belongs to the rastport record just created.
        let pointer = unsafe { sys::sdk_gfx_rastport_ptr(context.key(), token) };
        // SAFETY: `pointer` is zeroed rastport memory of the right size;
        // InitRastPort sets its defaults and the bitmap is attached after.
        unsafe { sys::graphics::init_rast_port(library, pointer) };
        // SAFETY: the bitmap outlives the rastport through the `'b` borrow.
        let attached = unsafe {
            sys::sdk_gfx_rastport_set_bitmap(context.key(), token, self.bitmap, &mut native_error)
        };
        if attached != 0 {
            // SAFETY: drop the record again; nothing else refers to it.
            unsafe { sys::sdk_gfx_rastport_drop(context.key(), token, &mut native_error) };
            return Err(refusal(native_error));
        }
        Ok(RastPort {
            graphics: self.graphics,
            token,
            pointer,
            width: self.width,
            height: self.height,
            filling: false,
            _bitmap: PhantomData,
        })
    }

    /// Copies a rectangle of this bitmap into `destination` (`BltBitMap`,
    /// minterm copy, all planes).
    ///
    /// The rectangle is clipped by the library to both bitmaps. Returns the
    /// number of planes copied.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library of the two bitmaps differs, or
    /// a size does not fit 16 bits.
    #[allow(clippy::too_many_arguments)]
    pub fn blit(
        &self,
        source_x: i16,
        source_y: i16,
        destination: &mut BitMap<'_, '_>,
        destination_x: i16,
        destination_y: i16,
        width: i16,
        height: i16,
    ) -> Result<i32, Error> {
        if !core::ptr::eq(self.graphics.context, destination.graphics.context) {
            return Err(Error::Invalid);
        }
        let library = self.graphics.base()?;
        // SAFETY: both bitmaps are live graphics.library bitmaps; the call
        // reads the first and writes the second.
        let planes = unsafe {
            sys::graphics::blt_bit_map(
                library,
                self.bitmap,
                source_x,
                source_y,
                destination.bitmap,
                destination_x,
                destination_y,
                width,
                height,
                MINTERM_COPY,
                0xff,
                core::ptr::null_mut(),
            )
        };
        // SAFETY: waits for the blitter to finish before the data is used.
        unsafe { sys::graphics::wait_blit(library) };
        Ok(planes)
    }
}

impl Drop for BitMap<'_, '_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = SdkError { kind: 0, native: 0 };
        // SAFETY: the bridge forgets the bitmap first so it is freed once.
        let released = unsafe {
            sys::sdk_gfx_bitmap_release(self.graphics.context.key(), token, &mut native_error)
        };
        if released == 0
            && let Ok(library) = self.graphics.base()
        {
            // SAFETY: the library is open and the bitmap is ours alone.
            unsafe {
                sys::graphics::wait_blit(library);
                sys::graphics::free_bit_map(library, self.bitmap);
            }
        }
    }
}

fn refusal(error: SdkError) -> Error {
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

mod sealed {
    pub trait Sealed {}
}

/// Something pixels can be drawn on: a [`RastPort`] or a [`RastPortRef`].
///
/// The trait is sealed. Coordinates are in pixels with the origin at the top
/// left; drawing outside the bitmap is clipped by the library.
pub trait Canvas: sealed::Sealed {
    #[doc(hidden)]
    fn parts(&self) -> Result<(*mut sys::Library, *mut c_void), Error>;

    /// Sets the foreground pen.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    fn set_pen(&mut self, pen: u32) -> Result<(), Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: valid library base and rastport.
        unsafe { sys::graphics::set_apen(library, rastport, pen) };
        Ok(())
    }

    /// Sets the background pen.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    fn set_background_pen(&mut self, pen: u32) -> Result<(), Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: valid library base and rastport.
        unsafe { sys::graphics::set_bpen(library, rastport, pen) };
        Ok(())
    }

    /// Sets the drawing mode.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    fn set_draw_mode(&mut self, mode: DrawMode) -> Result<(), Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: valid library base and rastport.
        unsafe { sys::graphics::set_dr_md(library, rastport, mode as u32) };
        Ok(())
    }

    /// Fills the whole canvas with `pen`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    fn clear(&mut self, pen: u32) -> Result<(), Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: valid library base and rastport.
        unsafe { sys::graphics::set_rast(library, rastport, pen) };
        Ok(())
    }

    /// Moves the drawing position without drawing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    fn move_to(&mut self, x: i16, y: i16) -> Result<(), Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: valid library base and rastport.
        unsafe { sys::graphics::move_to(library, rastport, x, y) };
        Ok(())
    }

    /// Draws a line from the drawing position to `(x, y)` in the foreground
    /// pen and moves the drawing position there.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    fn line_to(&mut self, x: i16, y: i16) -> Result<(), Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: valid library base and rastport.
        unsafe { sys::graphics::draw(library, rastport, x, y) };
        Ok(())
    }

    /// Draws a line between two points.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    fn line(&mut self, x1: i16, y1: i16, x2: i16, y2: i16) -> Result<(), Error> {
        self.move_to(x1, y1)?;
        self.line_to(x2, y2)
    }

    /// Fills the rectangle with corners `(x1, y1)` and `(x2, y2)`, inclusive,
    /// in the foreground pen.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    fn fill_rect(&mut self, x1: i16, y1: i16, x2: i16, y2: i16) -> Result<(), Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: valid library base and rastport.
        unsafe { sys::graphics::rect_fill(library, rastport, x1, y1, x2, y2) };
        Ok(())
    }

    /// Fills the rectangle with the background pen.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    fn erase_rect(&mut self, x1: i16, y1: i16, x2: i16, y2: i16) -> Result<(), Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: valid library base and rastport.
        unsafe { sys::graphics::erase_rect(library, rastport, x1, y1, x2, y2) };
        Ok(())
    }

    /// Draws the outline of an ellipse with horizontal radius `a` and vertical
    /// radius `b` around `(x, y)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    fn ellipse(&mut self, x: i16, y: i16, a: i16, b: i16) -> Result<(), Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: valid library base and rastport.
        unsafe { sys::graphics::draw_ellipse(library, rastport, x, y, a, b) };
        Ok(())
    }

    /// Draws the closed outline of a polygon through `points`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for fewer than two points or more than
    /// [`MAX_POLYGON_POINTS`].
    fn polygon(&mut self, points: &[(i16, i16)]) -> Result<(), Error> {
        if points.len() < 2 || points.len() > MAX_POLYGON_POINTS {
            return Err(Error::Invalid);
        }
        let (library, rastport) = self.parts()?;
        // PolyDraw draws from the current position to its first entry, so the
        // first vertex is a move and the table holds the rest and the way back.
        let mut table = [0i16; 2 * MAX_POLYGON_POINTS];
        for (slot, (x, y)) in table
            .chunks_exact_mut(2)
            .zip(points[1..].iter().chain(&points[..1]))
        {
            slot[0] = *x;
            slot[1] = *y;
        }
        // SAFETY: `table` holds `points.len()` coordinate pairs.
        unsafe {
            sys::graphics::move_to(library, rastport, points[0].0, points[0].1);
            sys::graphics::poly_draw(library, rastport, points.len() as i32, table.as_mut_ptr())
        };
        Ok(())
    }

    /// Draws `text` at the drawing position with the rastport's font and moves
    /// the drawing position to the end of it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for more than [`MAX_TEXT_BYTES`] bytes.
    fn text(&mut self, text: &[u8]) -> Result<(), Error> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(Error::Invalid);
        }
        let (library, rastport) = self.parts()?;
        // SAFETY: `text` is readable for its length.
        unsafe { sys::graphics::text(library, rastport, text.as_ptr().cast(), text.len() as u32) };
        Ok(())
    }

    /// Returns the width in pixels `text` would take.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for more than [`MAX_TEXT_BYTES`] bytes.
    fn text_length(&self, text: &[u8]) -> Result<i16, Error> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(Error::Invalid);
        }
        let (library, rastport) = self.parts()?;
        // SAFETY: `text` is readable for its length.
        Ok(unsafe {
            sys::graphics::text_length(library, rastport, text.as_ptr().cast(), text.len() as u32)
        })
    }

    /// Reads the pen number of a pixel, or `None` outside the canvas.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    fn read_pixel(&self, x: i16, y: i16) -> Result<Option<u32>, Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: valid library base and rastport.
        let value = unsafe { sys::graphics::read_pixel(library, rastport, x, y) };
        Ok(u32::try_from(value).ok())
    }

    /// Sets a pixel to the foreground pen.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    fn write_pixel(&mut self, x: i16, y: i16) -> Result<(), Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: valid library base and rastport.
        unsafe { sys::graphics::write_pixel(library, rastport, x, y) };
        Ok(())
    }

    /// Scrolls the canvas contents by `(dx, dy)` within the rectangle with
    /// corners `(x1, y1)` and `(x2, y2)`; the uncovered area takes the
    /// background pen.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if the library is no longer valid.
    #[allow(clippy::too_many_arguments)]
    fn scroll(
        &mut self,
        dx: i16,
        dy: i16,
        x1: i16,
        y1: i16,
        x2: i16,
        y2: i16,
    ) -> Result<(), Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: valid library base and rastport.
        unsafe { sys::graphics::scroll_raster(library, rastport, dx, dy, x1, y1, x2, y2) };
        Ok(())
    }

    /// Copies a rectangle of `source` onto the canvas (`BltBitMapRastPort`,
    /// minterm copy).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] if `source` belongs to another context.
    #[allow(clippy::too_many_arguments)]
    fn blit_from(
        &mut self,
        source: &BitMap<'_, '_>,
        source_x: i16,
        source_y: i16,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
    ) -> Result<(), Error> {
        let (library, rastport) = self.parts()?;
        // SAFETY: the bitmap is live; the call reads it and draws on the canvas.
        unsafe {
            sys::graphics::blt_bit_map_rast_port(
                library,
                source.bitmap,
                source_x,
                source_y,
                rastport,
                x,
                y,
                width,
                height,
                MINTERM_COPY,
            );
            sys::graphics::wait_blit(library);
        }
        Ok(())
    }
}

/// The rastport that draws into a [`BitMap`].
///
/// It borrows the bitmap mutably. The native bridge owns its memory and drops
/// it with the handle, or at program exit if it is forgotten.
pub struct RastPort<'b, 'g, 'ctx> {
    graphics: &'g Graphics<'ctx>,
    token: u64,
    pointer: *mut c_void,
    width: u16,
    height: u16,
    filling: bool,
    _bitmap: PhantomData<&'b mut ()>,
}

impl sealed::Sealed for RastPort<'_, '_, '_> {}

impl Canvas for RastPort<'_, '_, '_> {
    fn parts(&self) -> Result<(*mut sys::Library, *mut c_void), Error> {
        Ok((self.graphics.base()?, self.pointer))
    }
}

impl RastPort<'_, '_, '_> {
    /// Fills a polygon through `points` in the foreground pen.
    ///
    /// The first call sets up the fill buffers for this bitmap, which costs
    /// memory proportional to its size. The polygon is closed automatically.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for fewer than three points or more than
    /// [`MAX_POLYGON_POINTS`], [`Error::OutOfMemory`] if the buffers cannot be
    /// allocated, and [`Error::Failed`] if the library rejects a vertex.
    pub fn fill_polygon(&mut self, points: &[(i16, i16)]) -> Result<(), Error> {
        if points.len() < 3 || points.len() > MAX_POLYGON_POINTS {
            return Err(Error::Invalid);
        }
        let library = self.graphics.base()?;
        let key = self.graphics.context.key();
        if !self.filling {
            let mut native_error = SdkError { kind: 0, native: 0 };
            let max_vectors = (MAX_POLYGON_POINTS + 4) as i32;
            // SAFETY: valid key and rastport token.
            let prepared = unsafe {
                sys::sdk_gfx_area_prepare(
                    key,
                    self.token,
                    max_vectors,
                    i32::from(self.width),
                    i32::from(self.height),
                    &mut native_error,
                )
            };
            if prepared != 0 {
                return Err(if native_error.native == 103 {
                    Error::OutOfMemory
                } else {
                    refusal(native_error)
                });
            }
            // SAFETY: the bridge allocated these buffers for this rastport.
            unsafe {
                let area = sys::sdk_gfx_area_ptr(key, self.token, 0);
                let vectors = sys::sdk_gfx_area_ptr(key, self.token, 1);
                let tmpras = sys::sdk_gfx_area_ptr(key, self.token, 2);
                let raster = sys::sdk_gfx_area_ptr(key, self.token, 3);
                let raster_size = sys::sdk_gfx_area_size(key, self.token, 3);
                sys::graphics::init_area(library, area, vectors, max_vectors as i16);
                sys::graphics::init_tmp_ras(library, tmpras, raster.cast(), raster_size as u32);
                sys::sdk_gfx_area_attach(key, self.token, &mut native_error);
            }
            self.filling = true;
        }
        let (first_x, first_y) = points[0];
        // SAFETY: the area buffers are attached; the vertices are queued and
        // AreaEnd fills them.
        let result = unsafe {
            let mut ok = sys::graphics::area_move(library, self.pointer, first_x, first_y) == 0;
            for (x, y) in &points[1..] {
                ok &= sys::graphics::area_draw(library, self.pointer, *x, *y) == 0;
            }
            sys::graphics::area_end(library, self.pointer);
            ok
        };
        if result { Ok(()) } else { Err(Error::Failed) }
    }
}

impl Drop for RastPort<'_, '_, '_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = SdkError { kind: 0, native: 0 };
        // SAFETY: valid key and token; the record frees its memory.
        let _ = unsafe {
            sys::sdk_gfx_rastport_drop(self.graphics.context.key(), token, &mut native_error)
        };
    }
}

/// A rastport that something else owns, such as a window.
///
/// The reference is tied to the lifetime of its owner, so it cannot be used
/// after the owner is gone.
///
/// ```compile_fail
/// use aros_graphics::{Canvas, Graphics, RastPortRef};
///
/// fn escape(graphics: &Graphics<'_>) {
///     let mut reference;
///     {
///         let owner = 0u8;
///         // SAFETY: not a real rastport; this must not compile at all.
///         reference = unsafe { RastPortRef::borrow(graphics, core::ptr::null_mut(), &owner) };
///     }
///     // The owner has been dropped, so the reference cannot be used.
///     let _ = reference.clear(0);
/// }
/// ```
pub struct RastPortRef<'a, 'ctx> {
    graphics: &'a Graphics<'ctx>,
    pointer: *mut c_void,
    _owner: PhantomData<&'a ()>,
}

impl<'a, 'ctx> RastPortRef<'a, 'ctx> {
    /// Borrows a native rastport owned by `owner`.
    ///
    /// The result lives no longer than `owner`. Safe wrappers of window and
    /// screen types call this with the object that owns the rastport.
    ///
    /// # Safety
    ///
    /// `rastport` must point to a valid rastport that stays valid for as long
    /// as `owner` does, and must only be used by the task that owns `graphics`.
    pub unsafe fn borrow<T: ?Sized>(
        graphics: &'a Graphics<'ctx>,
        rastport: *mut c_void,
        owner: &'a T,
    ) -> Self {
        let _ = owner;
        Self {
            graphics,
            pointer: rastport,
            _owner: PhantomData,
        }
    }
}

impl sealed::Sealed for RastPortRef<'_, '_> {}

impl Canvas for RastPortRef<'_, '_> {
    fn parts(&self) -> Result<(*mut sys::Library, *mut c_void), Error> {
        Ok((self.graphics.base()?, self.pointer))
    }
}

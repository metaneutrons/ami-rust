//! Graphics cases: bitmaps, drawing primitives, blits and cleanup.

use core::mem;

use aros::Context;
use aros_graphics::{Canvas, DrawMode, Error, Graphics};

use super::{report_error, same_resources};

unsafe extern "C" {
    fn sdk_test_avail_mem() -> u64;
}

/// FNV-1a digest of the 64 by 48 scene (lines, rectangle, ellipse, outline,
/// pixel) recorded on the pinned ABI-v1 and ABI-v11 images; it is identical on both.
const EXPECTED_SCENE_DIGEST: u64 = 15891181435495386329;
/// The same scene after the polygon fill; it differs between the two ABIs.
#[cfg(not(all(target_os = "aros", target_abi = "abi11")))]
const EXPECTED_FILL_DIGEST: u64 = 442875060644236561;
#[cfg(all(target_os = "aros", target_abi = "abi11"))]
const EXPECTED_FILL_DIGEST: u64 = 2751563836365198462;
const WIDTH: u16 = 64;
const HEIGHT: u16 = 48;

fn fnv(hash: u64, value: u64) -> u64 {
    (hash ^ value).wrapping_mul(0x0000_0100_0000_01b3)
}

fn digest<C: Canvas>(canvas: &C, width: i16, height: i16) -> Option<u64> {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for y in 0..height {
        for x in 0..width {
            hash = fnv(hash, u64::from(canvas.read_pixel(x, y).ok()??));
        }
    }
    Some(hash)
}

fn pixel<C: Canvas>(canvas: &C, x: i16, y: i16) -> Option<u32> {
    canvas.read_pixel(x, y).ok().flatten()
}

/// The scene every check and the digest refer to.
fn draw_scene<C: Canvas>(canvas: &mut C) -> Result<(), Error> {
    canvas.set_pen(1)?;
    canvas.fill_rect(4, 4, 30, 20)?;
    canvas.set_pen(2)?;
    canvas.line(0, 47, 63, 47)?;
    canvas.set_pen(3)?;
    canvas.ellipse(44, 14, 16, 8)?;
    canvas.set_pen(4)?;
    canvas.polygon(&[(4, 26), (20, 26), (20, 34), (4, 34)])?;
    canvas.set_pen(6)?;
    canvas.write_pixel(1, 1)
}

/// Text in the foreground pen only. The default fonts of the two ABIs differ in
/// size, and the library fills the text cell with the background pen unless the
/// mode is JAM1, so the text is drawn last and compared separately.
fn draw_text<C: Canvas>(canvas: &mut C) -> Result<(), Error> {
    canvas.set_draw_mode(DrawMode::Jam1)?;
    canvas.set_pen(6)?;
    canvas.move_to(6, 44)?;
    canvas.text(b"Hi")
}

/// Draws every primitive into an off-screen bitmap and checks sample pixels.
/// The digest of all pixels is recorded as a diagnostic; the expected digest of
/// each ABI is checked below.
fn primitives(context: &Context, graphics: &Graphics<'_>) -> Result<bool, Error> {
    let mut bitmap = graphics.bitmap(WIDTH, HEIGHT, 8)?;
    let mut rastport = bitmap.rastport()?;
    rastport.clear(0)?;
    if pixel(&rastport, 0, 0) != Some(0) || pixel(&rastport, WIDTH as i16, 0).is_some() {
        return Ok(false);
    }

    draw_scene(&mut rastport)?;
    // Lines, rectangles, ellipses, outlines and pixels are the same on both
    // ABIs: this digest is fixed.
    let scene = digest(&rastport, WIDTH as i16, HEIGHT as i16);
    context.diagnostic(b"qualification-gfx-scene-digest", scene.unwrap_or(0));
    // The area fill rounds its edges differently in the two graphics
    // libraries (one pixel on some rows), so its digest is fixed per ABI.
    rastport.set_pen(5)?;
    rastport.fill_polygon(&[(30, 30), (56, 30), (43, 44)])?;
    let filled = digest(&rastport, WIDTH as i16, HEIGHT as i16);
    context.diagnostic(b"qualification-gfx-fill-digest", filled.unwrap_or(0));
    draw_text(&mut rastport)?;

    let checks = [
        (10, 10, 1),
        (30, 20, 1),
        (3, 3, 0),
        (31, 21, 0),
        (0, 47, 2),
        (63, 47, 2),
        (4, 26, 4),
        (20, 34, 4),
        (43, 33, 5),
        (1, 1, 6),
    ];
    if scene != Some(EXPECTED_SCENE_DIGEST) || filled != Some(EXPECTED_FILL_DIGEST) {
        return Ok(false);
    }
    for (x, y, want) in checks {
        if pixel(&rastport, x, y) != Some(want) {
            context.diagnostic(b"qualification-gfx-pixel", ((x as u64) << 16) | y as u64);
            context.diagnostic(
                b"qualification-gfx-pixel-value",
                u64::from(pixel(&rastport, x, y).unwrap_or(999)),
            );
            // Show the neighbourhood as one text row per scan line.
            for row in (y - 4).max(0)..(y + 5).min(HEIGHT as i16) {
                let mut line = [b'.'; 24];
                for (column, cell) in line.iter_mut().enumerate() {
                    let at = (x - 12).max(0) + column as i16;
                    if let Some(value) = pixel(&rastport, at, row) {
                        *cell = b"0123456789abcdef"[(value & 15) as usize];
                    }
                }
                context.diagnostic(&line, row as u64);
            }
            return Ok(false);
        }
    }
    // The ellipse is centred at (44, 14): its extremes are on pen 3.
    if pixel(&rastport, 44, 6) != Some(3) || pixel(&rastport, 28, 14) != Some(3) {
        return Ok(false);
    }
    // Text drew something in pen 6 around its start and has a width.
    let width = rastport.text_length(b"Hi")?;
    let mut text_pixels = 0;
    for y in 30..48 {
        for x in 6..(6 + width + 2) {
            text_pixels += u32::from(pixel(&rastport, x, y) == Some(6));
        }
    }
    context.diagnostic(b"qualification-gfx-text-width", width as u64);
    context.diagnostic(b"qualification-gfx-text-pixels", u64::from(text_pixels));
    if width <= 0 || text_pixels == 0 {
        return Ok(false);
    }

    // Drawing modes: complement changes pixels, JAM1 restores a known state.
    rastport.set_draw_mode(DrawMode::Complement)?;
    rastport.fill_rect(10, 10, 12, 12)?;
    let flipped = pixel(&rastport, 11, 11);
    rastport.fill_rect(10, 10, 12, 12)?;
    let restored = pixel(&rastport, 11, 11);
    rastport.set_draw_mode(DrawMode::Jam1)?;
    if flipped == Some(1) || restored != Some(1) {
        return Ok(false);
    }

    // Out-of-range polygons are refused before any native call.
    if rastport.polygon(&[(0, 0)]) != Err(Error::Invalid)
        || rastport.fill_polygon(&[(0, 0), (1, 1)]) != Err(Error::Invalid)
    {
        return Ok(false);
    }

    let hash = digest(&rastport, WIDTH as i16, HEIGHT as i16);
    context.diagnostic(b"qualification-gfx-digest", hash.unwrap_or(0));
    Ok(hash.is_some())
}

/// Scrolling moves contents: positive dx moves them to the left and the
/// uncovered area takes the background pen.
fn scrolling(graphics: &Graphics<'_>) -> Result<bool, Error> {
    let mut bitmap = graphics.bitmap(16, 16, 8)?;
    let mut rastport = bitmap.rastport()?;
    rastport.clear(0)?;
    rastport.set_pen(7)?;
    rastport.write_pixel(8, 8)?;
    rastport.scroll(3, 0, 0, 0, 15, 15)?;
    Ok(pixel(&rastport, 5, 8) == Some(7)
        && pixel(&rastport, 8, 8) == Some(0)
        && pixel(&rastport, 14, 8) == Some(0))
}

fn blits(context: &Context, graphics: &Graphics<'_>) -> Result<bool, Error> {
    let mut source = graphics.bitmap(16, 16, 8)?;
    {
        let mut rastport = source.rastport()?;
        rastport.clear(9)?;
        rastport.set_pen(10)?;
        rastport.fill_rect(0, 0, 3, 3)?;
    }
    let mut target = graphics.bitmap(WIDTH, HEIGHT, 8)?;
    // BltBitMap: eleven arguments through the generated adapter.
    let planes = source.blit(0, 0, &mut target, 40, 30, 16, 16)?;
    context.diagnostic(b"qualification-gfx-blt-planes", planes as u64);
    let mut ok = {
        let rastport = target.rastport()?;
        pixel(&rastport, 40, 30) == Some(10)
            && pixel(&rastport, 43, 33) == Some(10)
            && pixel(&rastport, 44, 34) == Some(9)
            && pixel(&rastport, 55, 45) == Some(9)
            && pixel(&rastport, 39, 30) == Some(0)
    };
    // BltBitMapRastPort: nine arguments, copying again at another place.
    let mut rastport = target.rastport()?;
    rastport.blit_from(&source, 0, 0, 2, 2, 8, 8)?;
    ok = ok
        && pixel(&rastport, 2, 2) == Some(10)
        && pixel(&rastport, 9, 9) == Some(9)
        && pixel(&rastport, 10, 10) == Some(0);
    Ok(ok)
}

pub fn cases(context: &Context) -> bool {
    let baseline = context.statistics();
    let graphics = match Graphics::open(context) {
        Ok(graphics) => graphics,
        Err(error) => {
            if let Error::Aros(error) = error {
                report_error(context, error);
            }
            return false;
        }
    };
    // Argument checks before any native call.
    let refusals = graphics.bitmap(0, 10, 8).err() == Some(Error::Invalid)
        && graphics.bitmap(10, 0, 8).err() == Some(Error::Invalid)
        && graphics.bitmap(10, 10, 0).err() == Some(Error::Invalid)
        && graphics.bitmap(10, 10, 9).err() == Some(Error::Invalid)
        && graphics.bitmap(40_000, 10, 8).err() == Some(Error::Invalid);
    if !refusals {
        return false;
    }
    match primitives(context, &graphics) {
        Ok(true) => {}
        _ => return false,
    }
    match blits(context, &graphics) {
        Ok(true) => {}
        _ => return false,
    }
    match scrolling(&graphics) {
        Ok(true) => {}
        _ => return false,
    }
    drop(graphics);
    same_resources(baseline, context.statistics())
}

/// Leaves a large bitmap, a rastport with fill buffers and the library to the
/// native end-of-run cleanup.
pub fn forgotten(context: &Context) -> bool {
    let baseline = context.statistics();
    let Ok(graphics) = Graphics::open(context) else {
        return false;
    };
    let Ok(mut bitmap) = graphics.bitmap(2048, 2048, 8) else {
        return false;
    };
    let Ok(mut rastport) = bitmap.rastport() else {
        return false;
    };
    let ok = rastport.fill_polygon(&[(0, 0), (100, 0), (50, 80)]).is_ok();
    let live = context.statistics();
    context.diagnostic(b"qualification-gfx-forgotten", live.bitmaps as u64);
    let ok = ok && live.bitmaps == baseline.bitmaps + 1 && live.rastports == baseline.rastports + 1;
    mem::forget(rastport);
    mem::forget(bitmap);
    mem::forget(graphics);
    ok
}

/// Prints the free memory so two runs can be compared.
pub fn available(context: &Context) -> bool {
    // SAFETY: a testing-only native control that reads Exec's free memory.
    context.diagnostic(b"qualification-avail-mem", unsafe { sdk_test_avail_mem() });
    true
}

/// Prints the scene as one text row per scan line, one character per pen
/// (0 to 9 and a to f), so the result of two ABIs can be compared by eye.
pub fn dump(context: &Context) -> bool {
    let Ok(graphics) = Graphics::open(context) else {
        return false;
    };
    let Ok(mut bitmap) = graphics.bitmap(WIDTH, HEIGHT, 8) else {
        return false;
    };
    let Ok(mut rastport) = bitmap.rastport() else {
        return false;
    };
    if rastport.clear(0).is_err()
        || draw_scene(&mut rastport).is_err()
        || rastport.set_pen(5).is_err()
        || rastport
            .fill_polygon(&[(30, 30), (56, 30), (43, 44)])
            .is_err()
    {
        return false;
    }
    for y in 0..HEIGHT as i16 {
        let mut line = [b'.'; WIDTH as usize];
        for (x, cell) in line.iter_mut().enumerate() {
            if let Some(value) = pixel(&rastport, x as i16, y) {
                *cell = b"0123456789abcdef"[(value & 15) as usize];
            }
        }
        context.diagnostic(&line, y as u64);
    }
    true
}

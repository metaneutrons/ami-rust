---
title: The aros-graphics crate
description: "Off-screen bitmaps and drawing on graphics.library: pens, lines, rectangles, ellipses, polygons, text, pixels and blits."
---

`aros-graphics` draws into off-screen bitmaps through `graphics.library` for an active `aros::Context`. It is `no_std`, allocates nothing on the Rust heap and is the same on ABI-v1 and ABI-v11. The rules shared by every handle are in the [programming model](/api/); every item is listed in the [reference](/reference/aros_graphics/). It is available from the repository after release 0.1.0 and is not part of that release. Windows and screens come with the Intuition crate; until then the borrowed form `RastPortRef` is the way to draw on a rastport that something else owns.

| Item | Use |
| --- | --- |
| `Graphics::open(context)` | Opens `graphics.library` (version 39 or newer) and owns the reference. |
| `Graphics::bitmap(width, height, depth)` → `BitMap` | Allocates an off-screen bitmap of 1 to 8 bits per pixel, cleared to pen 0. Each pixel is a pen number. |
| `BitMap::rastport()` → `RastPort` | The rastport that draws into the bitmap. It borrows the bitmap mutably. |
| `BitMap::blit(...)` | Copies a rectangle between two bitmaps (`BltBitMap`). |
| `RastPortRef::borrow(graphics, pointer, owner)` | Unsafe constructor of a rastport reference whose lifetime is tied to `owner`. |
| `Canvas` methods | `set_pen`, `set_background_pen`, `set_draw_mode`, `clear`, `move_to`, `line_to`, `line`, `fill_rect`, `erase_rect`, `ellipse`, `polygon`, `text`, `text_length`, `read_pixel`, `write_pixel`, `scroll`, `blit_from`. Implemented by `RastPort` and `RastPortRef`. |
| `RastPort::fill_polygon(points)` | Fills a polygon (`AreaMove`, `AreaDraw`, `AreaEnd`). Bitmap rastports only. |

```rust
use aros::{Context, Error};
use aros_graphics::{Canvas, Graphics};

fn draw_square(context: &Context) -> Result<(), aros_graphics::Error> {
    let graphics = Graphics::open(context)?;
    let mut bitmap = graphics.bitmap(64, 48, 8)?;
    let mut rastport = bitmap.rastport()?;
    rastport.set_pen(1)?;
    rastport.fill_rect(4, 4, 30, 20)?;
    rastport.set_pen(2)?;
    rastport.polygon(&[(40, 4), (60, 4), (60, 24), (40, 24)])?;
    rastport.set_pen(3)?;
    rastport.fill_polygon(&[(4, 30), (30, 30), (17, 44)])?;
    let inside = rastport.read_pixel(10, 10)?;
    context.diagnostic(b"pen at 10,10", u64::from(inside.unwrap_or(999)));
    Ok(())
}
```

## Ownership and cleanup

A `RastPort` borrows its `BitMap` mutably and a `BitMap` borrows its `Graphics`, so a bitmap cannot be freed or used by a blit while a rastport draws into it and the library stays open while either exists. `BitMap::blit` takes the source by shared and the destination by mutable reference, so a bitmap cannot be blitted onto itself; to copy within one bitmap use `Canvas::scroll`. A `RastPortRef` carries the lifetime of the object that owns the rastport and cannot outlive it; a rustdoc `compile_fail` example in the crate checks this.

The native bridge owns the memory of every rastport and of the buffers an area fill needs, and it records every bitmap with the library base it came from. A rastport or bitmap that the program forgets is released when the program finishes, before the libraries are closed. The qualification fixture allocated a 2048 by 2048, 8-bit bitmap and a rastport with fill buffers, forgot them, and the free memory reported by Exec was the same afterwards as before on both ABIs, run after run.

## Limits and behaviour

- A bitmap is 1 to 32,767 pixels on a side with a depth of 1 to 8. Zero sides, larger sides and other depths are `Error::Invalid` before any library call. Truecolor bitmaps are not offered.
- A polygon has at most 256 points, and `fill_polygon` needs three. A fill allocates a vertex buffer and a one-bit scratch raster the size of the bitmap on its first use; that memory belongs to the rastport.
- Text is at most 65,535 bytes per call. The default font is whatever the library gives a new rastport.
- Coordinates are 16-bit. Drawing outside the bitmap is clipped by the library, and `read_pixel` returns `None` there.
- `polygon` draws the closed outline. `PolyDraw` itself draws from the current position, so the crate moves to the first vertex first.
- Blits and the scroll wait for the blitter before returning.

## ABI differences

The same drawing calls were run on the pinned ABI-v1 and ABI-v11 images and every pixel of a 64 by 48, 8-bit bitmap was read back. These observations are of that profile:

- Lines, a filled rectangle, an ellipse, a polygon outline and a single pixel produce **identical** pixels on both ABIs; the fixture compares one FNV-1a digest of all pixels.
- A **filled polygon** differs: the two graphics libraries round the slanted edges of a triangle differently, by one pixel on some rows. The fixture keeps one expected digest per ABI. Do not compare filled-polygon output across ABIs byte for byte.
- **Text** has the same width for the same string (16 pixels for `Hi`), but the default fonts differ in glyph shapes and height, so the pixels set differ (39 and 40 for that string). With `DrawMode::Jam2`, the default, the library also fills the whole text cell with the background pen, which can erase lines drawn there earlier. Set `DrawMode::Jam1` before drawing text over other content.
- Both ABIs agree on blits: `BltBitMap` (eleven arguments) and `BltBitMapRastPort` (nine) copy the same pixels. On ABI-v11 their stack-passed arguments use the generated adapter described in [Targets and ABIs](/targets-and-abis/).

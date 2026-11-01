# aros-graphics

Bitmaps and drawing for the selected AROS ABI profile, on top of
`graphics.library`. `Graphics::open` owns the library reference. A `BitMap` is
an off-screen bitmap with a depth of one to eight bits (pen values), and
`BitMap::rastport` creates the `RastPort` that draws into it. The `Canvas`
methods cover pens and drawing modes, lines, rectangles, ellipses, polygons
(outline and filled), text, pixel access and blits, and work the same on a
`RastPort` and on a `RastPortRef`, the borrowed form for a rastport that
something else owns, such as a window.

The crate is `no_std`, allocates nothing on the Rust heap and is the same on
ABI-v1 and ABI-v11. Bitmaps and rastports are tracked by the native bridge and
released at program exit if they are forgotten.

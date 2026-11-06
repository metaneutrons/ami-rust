# aros-intuition

Windows for the selected AROS ABI profile, on top of `intuition.library`.
`Intuition::open` owns the library reference, `PubScreen::lock` locks a public
screen, and `WindowBuilder` opens a `Window` with a tag list built on the
stack. `Window::next_event` returns typed events (close, keys, mouse buttons
and movement, refresh, resize) from the window's IDCMP port, and
`Window::signal_mask` lets a program wait for them in `aros::wait_signals`
together with other signal sources such as timers. `Window::rastport` lends the
window's rastport to `aros-graphics` as a `RastPortRef` that cannot outlive the
window.

The crate is `no_std`, allocates nothing on the Rust heap and is the same on
ABI-v1 and ABI-v11. The native bridge owns each window's title text and
records every window and screen lock, so a forgotten window is closed and a
forgotten lock released when the program ends.

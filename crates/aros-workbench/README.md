# aros-workbench

The application side of Workbench for the selected AROS ABI profile, on top of
`workbench.library`. `Workbench::open` owns the library reference and
`AppPort` is the message port Workbench sends to. `AppWindow` makes an
`aros-intuition` window accept dropped icons, `AppIcon` puts an icon on the
Workbench desktop and `AppMenuItem` adds an item to the Workbench Tools menu;
`AppPort::next` returns typed `AppMessage`s with the dropped paths as owned
values, and `AppPort::signal_mask` goes into `aros::wait_signals`.
The raw `SendAppWindowMessage` call (`aros_sys::workbench`) delivers a drop to
one's own `AppWindow` from a second task, which is how the drop path is tested
without a user dragging an icon; it is synchronous, so the crate has no safe
wrapper for it.

The crate is `no_std`, allocates nothing on the Rust heap and is the same on
ABI-v1 and ABI-v11. The native bridge owns the message port and the registered
texts, removes every registration when the program ends and returns pending
messages, so nothing is left behind.

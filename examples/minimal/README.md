# ami-rust-minimal

Minimal native startup and ABI reference application. It checks selected layout
values, scalar calls, callback dispatch, resource counters and, with the `alloc`
feature, one allocation cycle.

The package uses ordinary Cargo with the pinned `aros-native-build` helper and
the `x86_64-aros` target libraries. Build without default features for the
`minimal-noalloc` variant or with `alloc` for `minimal-alloc`. This is a
qualification fixture, not a general command-line application.

# std-probe

Native probe for the `std` spike. It is not a workspace member: it needs a toolchain that
ships `std` (see `examples/std-runtime/README.md`), and cannot build against the stock
`rust-src`.

It is an ordinary `fn main` program that enters its application function through
`aros::dispatch`. It needs a toolchain whose target specifications rename the
entry that rustc generates; `examples/std-runtime/README.md` explains the start-up
and how to build with such a toolchain. `aros::entry!` cannot be used here because
it installs a `#[panic_handler]`, which `std` already provides. The probe uses `std` for `Vec`, `format!`, `HashMap`, an
over-aligned allocation, `io::Error`, a thread-local, `Once` and `Mutex`, a thread, and
writes its results through a hand-declared C `write`.

Build with a toolchain `NAME` that ships `std`, as `examples/std-runtime/README.md` describes:

```sh
cd examples/std-probe
for target in x86_64-unknown-aros-abi1 x86_64-unknown-aros-abi11; do
  env CARGO_BUILD_RUSTC_WRAPPER= RUSTC_WRAPPER= \
    CARGO_TARGET_DIR="$work/probe-target" \
    cargo +NAME build --release --target "$target" --offline --locked
done
```

The program starts with `#![feature(restricted_std)]`, as every crate that uses this `std` must: the patch does not mark AROS as a supported platform, which keeps `std` on AROS visibly experimental. Without the attribute the build fails with a message that names it.

A passing run writes `std-probe: all checks passed` and returns status 0.

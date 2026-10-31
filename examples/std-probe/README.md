# std-probe

Native probe for the `std` spike. It is not a workspace member: it needs the
patched `std` from `host/std-aros/` and cannot build against the stock
`rust-src`.

The program has no `fn main`. It exports the `rust_sdk_main` symbol that the
native C start-up already calls and enters its application function through
`aros::dispatch`, so the 0.1 start-up contract is unchanged. `aros::entry!`
cannot be used here because it installs a `#[panic_handler]`, which `std`
already provides. The probe uses `std` for `Vec`, `format!`, `HashMap`, an
over-aligned allocation, `io::Error`, a thread-local, `Once` and `Mutex`, and
writes its results through a hand-declared C `write`.

Build, with the patched library tree prepared as described in
`host/std-aros/README.md` and called `$work/rust` there:

```sh
cd examples/std-probe
for target in x86_64-unknown-aros-abi1 x86_64-unknown-aros-abi11; do
  env CARGO_BUILD_RUSTC_WRAPPER= RUSTC_WRAPPER= \
    __CARGO_TESTS_ONLY_SRC_ROOT="$work/rust/library" \
    CARGO_TARGET_DIR="$work/probe-target" \
    cargo +0.1.0 build --release --target "$target" --offline --locked
done
```

A passing run writes `std-probe: all checks passed` and returns status 0.

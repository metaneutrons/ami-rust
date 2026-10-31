# `std` for AROS patch set (spike)

`std-aros.patch` adds a `target_os = "aros"` selection to the Rust standard
library of the pinned toolchain (`nightly-2026-09-18`, toolchain `0.1.0`). It is
a unified diff against the `rust-src` component, applied from
`lib/rustlib/src/rust` with `-p1`. `source.json` binds the base inventory pins,
the patch digest and the before and after digest of every changed file. Apply
the patch to a copy of `rust-src`; never edit the installed component.

The patch touches only `library/std`. It implements the five subsystems that
have no fallback for an unknown OS on the AROS C library, and leaves every
other subsystem on the `unsupported` fallback:

| Subsystem | Selection |
| --- | --- |
| `sys/alloc` | New `aros.rs` on `malloc`, `calloc`, `realloc`, `free` and `posix_memalign` |
| `sys/io/error` | New `aros.rs`: `errno` through the C library accessor, NetBSD errno table, `strerror` |
| `sys/random` | New `aros.rs`: weak clock and address mixing, no `getrandom` |
| `sys/sync` | The existing `no_threads` implementations; their build guard no longer rejects AROS |
| `sys/thread_local` | The existing `no_threads` storage; guard and selection list gain AROS |
| `build.rs` | AROS is a known platform, so `std` needs no `restricted_std` |

## Reproduce

Run from the repository root with the `0.1.0` toolchain installed.

```sh
set -eu
repo=$(pwd -P)
work=$(mktemp -d)
cp -R "$(rustc +0.1.0 --print sysroot)/lib/rustlib/src/rust" "$work/rust"
echo "70c4875bddb841556f349ce8482552652529ea6fad0e21c15c2f142e9ff5fad5  host/std-aros/std-aros.patch" | shasum -a 256 -c
patch -p1 -d "$work/rust" < host/std-aros/std-aros.patch
```

Build `std` offline from the vendored sources for both targets. The vendor
directory travels with `rust-src`; the build must see it as the only source,
as the pinned producer does:

```sh
mkdir "$work/cargo-home" "$work/probe"
printf '[source.crates-io]\nreplace-with = "vendor"\n[source.vendor]\ndirectory = "%s"\n' \
  "$work/rust/library/vendor" > "$work/cargo-home/config.toml"
cd "$work/probe"
mkdir src .cargo
printf '[package]\nname = "std-probe"\nversion = "0.0.0"\nedition = "2024"\n[workspace]\n' > Cargo.toml
printf 'pub fn hello(n: u32) -> String {\n    let mut map = std::collections::HashMap::new();\n    map.insert("answer", n);\n    format!("{map:?}")\n}\n' > src/lib.rs
printf '[unstable]\nbuild-std = ["std", "panic_abort"]\nbuild-std-features = ["compiler-builtins-mem"]\n' > .cargo/config.toml
CARGO_HOME="$work/cargo-home" cargo +0.1.0 generate-lockfile --offline
for target in x86_64-unknown-aros-abi1 x86_64-unknown-aros-abi11; do
  env CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$work/target" \
    CARGO_BUILD_RUSTC_WRAPPER= RUSTC_WRAPPER= \
    __CARGO_TESTS_ONLY_SRC_ROOT="$work/rust/library" \
    RUSTFLAGS=-Zunstable-options \
    cargo +0.1.0 build --lib --release --target "$target" --offline --locked
done
```

`__CARGO_TESTS_ONLY_SRC_ROOT` is Cargo's own override for the library source
directory. The pinned pipeline stages a private sysroot instead and does not
need it.

To run the native probe, point the same variable at the patched library and
build `examples/std-probe` (see `docs/plans/std-m1-spike-findings.md`).

## Limits

`std` on this patch has no threads: `thread::spawn` returns `Unsupported` and
the synchronisation types are the single-task implementations. Every API
outside the five subsystems is the `unsupported` fallback and fails at run
time, for example `Instant::now` and `std::process::exit`.

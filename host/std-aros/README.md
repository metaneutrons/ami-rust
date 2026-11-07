# `std` for AROS patch set (spike)

`std-aros.patch` adds a `target_os = "aros"` selection to the Rust standard
library of the pinned toolchain (`nightly-2026-09-18`, toolchains `0.1.0` and
`0.2.0`, which ship the identical `rust-src`). It is
a unified diff against the `rust-src` component, applied from
`lib/rustlib/src/rust` with `-p1`. `source.json` binds the base inventory pins,
the patch digest and the before and after digest of every changed file. Apply
the patch to a copy of `rust-src`; never edit the installed component.

The patch touches only `library/std`. It implements the subsystems that have no
fallback for an unknown OS on the AROS C library, and the ones that STD-M2
needs for a program to start, stop and talk to its user, and leaves every other
subsystem on the `unsupported` fallback:

| Subsystem | Selection |
| --- | --- |
| `sys/alloc` | New `aros.rs` on `malloc`, `calloc`, `realloc`, `free` and `posix_memalign` |
| `sys/io/error` | New `aros.rs`: `errno` through the C library accessor, NetBSD errno table, `strerror`; and the DOS errors that the C library reports as `1000 + code` get their own kinds and texts |
| `sys/random` | New `aros.rs`: `getentropy` on ABI-v1; on ABI-v11 (which has none) the weak clock and address mixing with `RDRAND` mixed in when the CPU has it. It also exports `__ami_rust_random_source`, which a test reads to see which source was used |
| `sys/pal` | New `aros`: `abort_internal` enters the native fatal path (`sdk_fatal`), which ends the program with return code 20; this also covers every panic under `panic = "abort"`. It also defines `rust_sdk_main`, which the native `main` calls and which runs the entry of a `fn main` program (see `examples/std-runtime/README.md`). It also has `without_requesters`, which switches DOS requesters off around path calls through the bridge function `sdk_proc_window_set` |
| `sys/time` | New `aros.rs`: `Instant` on `CLOCK_MONOTONIC` and `SystemTime` on `CLOCK_REALTIME`, with the 32-bit `time_t` read as unsigned so that `SystemTime` is correct until 2106 |
| `sys/thread` | New `aros.rs`: `thread::sleep` on `nanosleep`; everything else about threads stays unsupported |
| `sys/fs` | New `aros.rs`: `File` and `OpenOptions` on the descriptors of the C library (open, read, write, seek, truncate, duplicate, sync) and `remove_file`; everything else in `std::fs` stays unsupported. Works around five behaviours of the C library, see `examples/std-fs/README.md` |
| `sys/args` | New `aros.rs`: `env::args` from the `__argc` and `__argv` that the C start-up stores |
| `sys/exit` | `process::exit` releases what the program holds (`sdk_end`) and then leaves with the code it was given (`_Exit`) |
| `sys/stdio` | New `aros.rs`: standard input, output and error on the file descriptors 0, 1 and 2 |
| `sys/env` | New `aros.rs`: `var`, `set_var` and `remove_var` on the DOS variables through the C library; `vars()` is always empty |
| `sys/sync` | The existing `no_threads` implementations; their build guard no longer rejects AROS |
| `sys/thread_local` | The existing `no_threads` storage; guard and selection list gain AROS |
| `build.rs` | Unchanged on purpose: AROS stays an unknown platform, so every crate that uses `std` declares `#![feature(restricted_std)]` |

## Reproduce

Run from the repository root with the `0.2.0` toolchain installed.

```sh
set -eu
repo=$(pwd -P)
work=$(mktemp -d)
cp -R "$(rustc +0.2.0 --print sysroot)/lib/rustlib/src/rust" "$work/rust"
echo "3253dab543447a5ac7b762d2b6c51ff7d1e24b8f4aa6852e171622d48a571e56  host/std-aros/std-aros.patch" | shasum -a 256 -c
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
printf '#![feature(restricted_std)]\npub fn hello(n: u32) -> String {\n    let mut map = std::collections::HashMap::new();\n    map.insert("answer", n);\n    format!("{map:?}")\n}\n' > src/lib.rs
printf '[unstable]\nbuild-std = ["std", "panic_abort"]\nbuild-std-features = ["compiler-builtins-mem"]\n' > .cargo/config.toml
CARGO_HOME="$work/cargo-home" cargo +0.2.0 generate-lockfile --offline
for target in x86_64-unknown-aros-abi1 x86_64-unknown-aros-abi11; do
  env CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$work/target" \
    CARGO_BUILD_RUSTC_WRAPPER= RUSTC_WRAPPER= \
    __CARGO_TESTS_ONLY_SRC_ROOT="$work/rust/library" \
    RUSTFLAGS=-Zunstable-options \
    cargo +0.2.0 build --lib --release --target "$target" --offline --locked
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

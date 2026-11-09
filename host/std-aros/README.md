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
| `sys/io/error` | New `aros.rs`: `errno` and `set_errno` through the C library accessor, NetBSD errno table, `strerror`; and the DOS errors that the C library reports as `1000 + code` get their own kinds and texts |
| `sys/random` | New `aros.rs`: `getentropy` on ABI-v1; on ABI-v11 (which has none) the weak clock and address mixing with `RDRAND` mixed in when the CPU has it. It also exports `__ami_rust_random_source`, which a test reads to see which source was used |
| `sys/pal` | New `aros`: `abort_internal` enters the native fatal path (`sdk_fatal`), which ends the program with return code 20; this also covers every panic under `panic = "abort"`. It also defines `rust_sdk_main`, which the native `main` calls and which runs the entry of a `fn main` program (see `examples/std-runtime/README.md`). It also has `without_requesters`, which switches DOS requesters off around path calls through the bridge function `sdk_proc_window_set`. Whether it does so is a flag that a program sets through `std::os::aros::fs`. Also `safe_point` (a thread ends there, the main task ends the program, when the program is ending) and `ClibLock`, under which `std` calls the C library and reads `errno` once a thread exists |
| `os/aros` | New `std::os::aros::fs`, behind the unstable feature `aros_ext`: `requesters`, `set_requesters` and `with_requesters`, which let a program turn DOS requesters back on for `std::fs`, at any time |
| `sys/time` | New `aros.rs`: `Instant` on `CLOCK_MONOTONIC` and `SystemTime` on `CLOCK_REALTIME`, with the 32-bit `time_t` read as unsigned so that `SystemTime` is correct until 2106; the same reading is used for file dates |
| `sys/thread` | New `aros.rs`: threads as DOS processes through the bridge (`sdk_thread_spawn`, `sdk_thread_join`, detach), `yield_now`, a default stack of 256 KiB, `available_parallelism` of 1, and `thread::sleep` on `nanosleep`; every wait is a safe point (see `sys/pal`) |
| `sys/fs` | New `aros.rs`: `File` and `OpenOptions` on the descriptors of the C library (open, read, write, seek, truncate, duplicate, sync), metadata (`stat64`, `lstat64`, `fstat64`), permissions (read-only through `chmod`), setting the date (`utimes`), `read_dir`, `create_dir`, `remove_dir`, `remove_file`, `rename` (never with an existing destination in the C library), `canonicalize` (through the bridge function `sdk_path_name`), and `copy`, `exists` and `remove_dir_all` from the common code. Links and locks stay unsupported. Works around the behaviours of the C library listed in `examples/std-fs/README.md` |
| `sys/path` | New `aros.rs`: the volume with its colon is the prefix of a path (`Prefix::DeviceNS`), a path with a volume is absolute, `path::absolute` resolves a leading `:` and leading slashes; and `to_dos_path`, which resolves `.` and `..` before a path goes to the C library |
| `sys/paths` | New `aros.rs`: `getcwd` and `chdir` (refuses a file), `temp_dir` is `T:`, path lists separated by `;`, `home_dir` is `None`, `current_exe` unsupported |
| `path.rs` | Two lines under `cfg!(target_os = "aros")`: the length of a `DeviceNS` prefix is the volume name itself, and it is followed directly by the path like a Windows drive, so `join` adds no slash after `RAM:` |
| `sys/args` | New `aros.rs`: `env::args` from the `__argc` and `__argv` that the C start-up stores |
| `sys/exit` | `process::exit` releases what the program holds (`sdk_end`) and then leaves with the code it was given (`_Exit`); in a thread it records the code and ends the thread (`sdk_thread_exit`) |
| `sys/stdio` | New `aros.rs`: standard input, output and error on the file descriptors 0, 1 and 2 |
| `sys/env` | New `aros.rs`: `var`, `set_var` and `remove_var` on the DOS variables through the C library; `vars()` is always empty; the calls are made under `ClibLock` |
| `sys/sync` | AROS uses the futex implementations of `Mutex`, `Condvar`, `RwLock`, `Once` and the thread parker, on a new `futex/aros.rs` that calls the bridge's futex on Exec signals |
| `sys/thread_local` | Key-based thread-locals (`os`) on a new `key/aros.rs` over task storage slots; destructors run when a thread ends, as on Xous |
| `build.rs` | Unchanged on purpose: AROS stays an unknown platform, so every crate that uses `std` declares `#![feature(restricted_std)]` |

## Reproduce

Run from the repository root with the `0.2.0` toolchain installed.

```sh
set -eu
repo=$(pwd -P)
work=$(mktemp -d)
cp -R "$(rustc +0.2.0 --print sysroot)/lib/rustlib/src/rust" "$work/rust"
echo "500bfa962925baa4005a2058b3529203e0c4ca307e39d1f502591a2ec9f2b623  host/std-aros/std-aros.patch" | shasum -a 256 -c
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

## How the toolchain uses it

The toolchain producer (`toolchain-producer`, in `tooling/crates/xtask`) applies this patch to its private copy of
the pinned `rust-src` and builds `std` and `panic_abort` with the other target libraries, for both targets. It applies
the patch in process and refuses any file that differs from the digests in `source.json`; the patch and `source.json` are
inputs of `release/rust-production-contract.json`. The `rust-src` component that the toolchain ships is not patched.
Whenever the patch changes, the digests in the contract, the target library pins and the constants of
`native_prefix_compose.rs` change with it (see "Updating the patch" in `CONTRIBUTING.md`).

## Limits

`std` on this patch supports threads, time, the file system, paths, random numbers, the environment and arguments, and
stdio; networking and processes are the `unsupported` fallback. The supported surface and its limits per ABI are in
`docs/plans/std-m3-findings.md`, `docs/plans/std-m4-findings.md` and the test programs' READMEs. A crate that uses
`std` still declares `#![feature(restricted_std)]`.

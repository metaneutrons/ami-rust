---
title: Crates and consumer guide
description: Which ami-rust crates to depend on, how to add them to a project, and complete minimal programs.
---

ami-rust is a standard Cargo cross-toolchain for PC x86-64 AROS, with a small set of crates you add to your project as ordinary dependencies. This page tells you which crates to use, how to depend on them, and shows two complete programs.

The Cargo **target** selects the AROS ABI, and your source is the same for both. See [targets and ABIs](/targets-and-abis/).

| Target | Select when the system runs |
| --- | --- |
| `x86_64-unknown-aros-abi1` | Upstream AROS, ABI-v1 |
| `x86_64-unknown-aros-abi11` | Deadwood's AROS, ABI-v11 |

## Select a crate

| Crate | Use it for | Safe boundary |
| --- | --- | --- |
| `aros` | Application entry, task-local context, Exec-backed allocation, files, streams, libraries, signals, local ports and messages | The default application crate |
| `aros-mui` | Typed MUI objects, ownership scopes, attributes, notifications, callbacks, requesters and the application loop | The preferred MUI crate |
| `aros-timer` | Time and timers: the monotonic clock, calendar and up time, sleeping and signalled alarms (in the repository after release 0.1.0, not part of it) | Safe, built on `aros` |
| `aros-graphics` | Off-screen bitmaps and drawing: pens, lines, rectangles, ellipses, polygons, text, pixels and blits (in the repository after release 0.1.0, not part of it) | Safe, built on `aros` |
| `aros-sys` | A raw AROS declaration or library vector call that `aros` does not cover yet | Unsafe: you own every pointer, library base and lifetime |
| `aros-mui-sys` | A raw MUI vector, class, tag or message that `aros-mui` does not model safely | Unsafe: you own the complete native contract |
| `aros-native-build` | A build dependency. Your `build.rs` calls `aros_native_build::prepare`; your application code never uses it. | Not an application API |

`aros-elf` and the tools in the repository are internal; see [architecture](/architecture/).

Start with `aros`, add `aros-mui` for a graphical interface, and reach for a `-sys` crate only when you can document the raw pointer, tag, vector and lifetime contract that prevents a safe wrapper. For the concepts behind the safe crates, read the [programming model](/api/).

## Depend on the crates

The crates are delivered through Git and are intentionally not on crates.io. Pin a release by its tag:

```toml
[dependencies]
aros = { git = "https://github.com/metaneutrons/ami-rust", tag = "v0.1.0", features = ["alloc"] }
aros-mui = { git = "https://github.com/metaneutrons/ami-rust", tag = "v0.1.0" }

[build-dependencies]
aros-native-build = { git = "https://github.com/metaneutrons/ami-rust", tag = "v0.1.0" }
```

Release tags are immutable, and `Cargo.lock` records the exact commit that the tag pointed to when you resolved, so commit it. Use the tag of the release you installed the toolchain for. See [releases and versions](/releases/) for how this documentation relates to each release.

## A minimal program

A text-mode program that prints one line. `Cargo.toml` needs only `aros` and the build dependency:

```toml
[package]
name = "hello-aros"
version = "0.1.0"
edition = "2024"

[dependencies]
aros = { git = "https://github.com/metaneutrons/ami-rust", tag = "v0.1.0", features = ["alloc"] }

[build-dependencies]
aros-native-build = { git = "https://github.com/metaneutrons/ami-rust", tag = "v0.1.0" }
```

`build.rs` compiles the native bridge that the SDK needs, inside Cargo's own output directory:

```rust
fn main() {
    aros_native_build::prepare(Default::default()).expect("AROS native bridge");
}
```

`src/main.rs`:

```rust
#![no_main]
#![no_std]

use aros::{AppStatus, Context, Stdout};

fn application(context: &Context) -> AppStatus {
    let written = Stdout::new(context)
        .and_then(|mut out| out.write_all(b"Hello from Rust on AROS\n"));
    match written {
        Ok(()) => AppStatus::Success,
        Err(_) => AppStatus::Error,
    }
}

aros::entry!(application);
```

`entry!` defines the native entry symbol and a panic handler, so use it exactly once in the final application crate. Use `entry!(application, alloc)` when your program needs the global allocator.

Add the [Cargo configuration](/quickstart-toolchain/#configure-cargo), build with `cargo +0.1.0 build --target x86_64-unknown-aros-abi11 --release`, and [run it on AROS](/run-on-aros/).

## A graphical program

The same project can open a MUI window. Add `aros-mui` to `[dependencies]` as shown above, then replace `src/main.rs`. This is the standalone form of the [MUI hello example](/mui-hello/):

```rust
#![no_main]
#![no_std]

use aros::{AppStatus, Context};
use aros_mui::{
    Error, LoopControl, Mui, ReturnId, Trigger,
    attributes::{
        ApplicationBase, ApplicationTitle, Frame, GroupHoriz, TextContents, WindowCloseGadget,
        WindowCloseRequest, WindowOpen, WindowTitle,
    },
    classes::{Application, Group, Text, Window},
    values::FrameValue,
};

fn run(context: &Context) -> Result<(), Error> {
    let mui = Mui::open(context)?;
    let result = mui.scope(|scope| {
        let heading = scope
            .builder::<Text>()
            .with::<TextContents>(c"Hello from Rust on AROS")?
            .with::<Frame>(FrameValue::Text)?
            .build()?;
        let root = scope
            .builder::<Group>()
            .with::<GroupHoriz>(false)?
            .build()?;
        root.adopt(heading)?;
        let window = scope
            .builder::<Window>()
            .with::<WindowTitle>(c"My AROS window")?
            .with::<WindowCloseGadget>(true)?
            .build()?;
        window.adopt(root)?;
        let app = scope
            .builder::<Application>()
            .with::<ApplicationBase>(c"MYAROSWINDOW")?
            .with::<ApplicationTitle>(c"My AROS window")?
            .build()?;
        app.adopt(window)?;
        window
            .notify::<WindowCloseRequest>(Trigger::Value(true))?
            .return_id(app, ReturnId::QUIT)?;
        window.set::<WindowOpen>(true)?;
        app.run(|_| LoopControl::Continue).map(|_| ())
    });
    mui.close()?;
    result
}

fn application(context: &Context) -> AppStatus {
    run(context).map_or(AppStatus::Error, |_| AppStatus::Success)
}

aros::entry!(application, alloc);
```

The application owns native MUI objects only inside `Mui::scope`. Children are attached with `adopt`, and the scope disposes the native roots when it returns. Do not move an object, hook, callback or custom-class handle out of that scope: the types prevent it.

## Build

The Cargo configuration, the toolchain and the `--locked --offline` workflow are on the [install and build](/quickstart-toolchain/) page. Every dependency, including these crates, must be built for the same target as your program.

## Scope and compatibility

0.1.0 supports `no_std` plus `alloc`, not full `std`. Its native evidence covers the qualified QEMU profiles for ABI-v1 and ABI-v11. It does not establish support for a different CPU, physical hardware, arbitrary crates, threads, networking or an AROS-hosted Rust compiler. See the [compatibility boundary](/compatibility/) and the [API reference](/reference/) for the exact limits.

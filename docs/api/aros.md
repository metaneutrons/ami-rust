---
title: aros API
description: The safe, task-affine foundation for AROS applications.
---

# `aros` API

`aros` is the `no_std` application crate for the qualified x86-64 AROS ABI-v1
and ABI-v11 targets. Every safe OS handle borrows the active `Context`, remains
on its creating task, and is released when dropped or when the runtime cleans
up after the entry function returns.

```rust
use aros::{AppStatus, Context};

fn application(context: &Context) -> AppStatus {
    context.diagnostic(b"started", 0);
    AppStatus::Success
}

aros::entry!(application, alloc);
```

## Context and entry

| Item | Use |
| --- | --- |
| `entry!(application)` | Defines the native entry symbol and a heap-free panic path. Use once in the final application crate. |
| `entry!(application, alloc)` | Also installs `ExecAllocator`; native allocation may still fail. |
| `AppStatus` | Return `Success`, `Error`, or `Fatal` from the entry function. |
| `Context` | Borrowed proof of the active application task. Use it to create every safe SDK handle. |
| `Context::args()` | Iterates borrowed argument bytes. Argument strings need not be UTF-8. |
| `Context::diagnostic(label, code)` | Emits a bounded, allocation-free diagnostic. |
| `Context::statistics()` | Returns an `aros_sys::SdkStats` snapshot without allocating. |
| `ExecAllocator` | Global allocator backed by public Exec allocation. Available with the default `alloc` feature. |

`Context`, its iterator, and all handles derived from it are neither `Send` nor
`Sync`. They cannot escape the entry function or move to another AROS task.

## Errors and bounds

All fallible safe operations return `Result<_, aros::Error>`. `ErrorKind`
distinguishes native failure, invalid input, a documented limit, a wrong task
owner, invalid state, end of file, and zero progress. `Operation` identifies
the operation that failed; `Error::kind_code()` supplies an allocation-free
numeric classification for diagnostics.

The initial SDK uses bounded native registries: 16 open files, 4 optional
libraries, 2 private ports, 4 signal slots, and 8 owned messages with payloads
of at most 256 bytes. Paths allow 127 bytes before their terminating NUL; one
file or stream transfer is at most 64 KiB. These are API limits, not a heap
quota. Exec allocation can still fail when native memory is exhausted.

## File and stream I/O

`BytePath::new(&[u8])` creates a non-UTF-8 path after rejecting embedded NUL
bytes and an overlong payload. `File::open` accepts these modes:

| Mode | Native intent |
| --- | --- |
| `FileMode::ReadExisting` | Open an existing file; fail when it is absent. |
| `FileMode::CreateTruncate` | Create or replace a file. |
| `FileMode::ReadWrite` | Open or create a read/write file. |

`File` provides `read`, `write`, `read_exact`, `write_all`, and consuming
`close`. Single reads and writes may make partial progress; the `*_exact` and
`*_all` variants continue until complete or return an error. `Stdout` and
`Stderr` offer `write` and `write_all` on borrowed DOS process handles; neither
closes its underlying handle.

## Libraries, signals, and local messages

| Item | Use |
| --- | --- |
| `Library::open(context, name, minimum_version)` | Opens an owned optional-library reference. |
| `Signal::new(context)` | Allocates a task-local signal; use `post` and `wait`. |
| `wait_signals(context, mask)` | Waits for a raw mask in the active task. |
| `Port::new(context)` | Creates a private local message port. |
| `Message::new(context, payload)` | Owns bounded payload and native message storage. |
| `Port::send(message, reply)` | Queues a message and defines its reply route. |
| `Port::receive(message)` | Checks whether that supplied message is queued here; it does not drain arbitrary messages. |
| `Message::reply()` | Replies to a received local message. |

`aros::call(context, &mut callback, input)` invokes a `FnMut(u64) -> u64`
synchronously. Its callback frame cannot be retained by native code.
`Library::raw_base` is deliberately unsafe and lifetime-bound. Prefer a focused
safe crate such as [`aros-mui`](https://ami-rust.metaneutrons.cc/api/aros-mui/)
for higher-level library APIs.

---
title: The aros crate
description: "Entry, context, files, streams, libraries, signals, ports and messages: the safe foundation for AROS applications."
---

`aros` is the `no_std` application crate for the qualified x86-64 AROS ABI-v1
and ABI-v11 targets. Every safe OS handle borrows the active `Context`, remains
on its creating task, and is released when dropped or when the runtime cleans
up after the entry function returns. The rules shared by every handle are in
the [programming model](/api/); every item is listed in the
[reference](/reference/aros/).

```rust
#![no_main]
#![no_std]

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

The native registries for open files, optional libraries, private ports and
owned messages grow on demand. Memory is their practical bound, and each kind
has a token space of 1,048,575 handles; reaching it returns `ErrorKind::Limit`.
Running out of memory while a registry grows returns `ErrorKind::Native`.
Signals are the exception: Exec allocates them from one 32-bit task mask, so
only the bits Exec leaves free are available, and the rest returns
`ErrorKind::Native`. Owned messages carry payloads of at most 256 bytes. Paths
allow 127 bytes before their terminating NUL; one file or stream transfer is at
most 64 KiB.

Release 0.1.0 used fixed registries of 16 files, 4 libraries, 2 ports, 4
signals and 8 messages. Programs written for those limits keep working;
they simply no longer meet them.

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
safe crate such as [`aros-mui`](/api/aros-mui/)
for higher-level library APIs.

## Devices and I/O requests

| Item | Use |
| --- | --- |
| `Device::open(context, name, unit, flags)` | Opens an Exec device and owns the reply port its requests share. |
| `Device::signal_mask()` | The signal mask of that reply port, for `wait_signals`. |
| `Request::new(device, kind, data_capacity)` | Creates an idle request owning its `IORequest` and a bounded data area. |
| `Request::prepare`, `write_data`, `set_time` | Set up an idle request (command, flags, length, offset, data, time value). |
| `Request::do_io()` | Runs the request synchronously (`DoIO`). |
| `Request::send()`, `check()`, `wait()`, `abort()` | Run it asynchronously (`SendIO`, `CheckIO`, `WaitIO`, `AbortIO`). |
| `Request::outcome()`, `read_data`, `time` | Read the device error, transferred byte count, data and time value of an idle request. |

A request is idle or pending. Dropping or closing a pending request aborts it
and waits for the device to return it, so no message stays queued, and
forgotten requests and devices are aborted and closed when the program
finishes. A `Request` borrows its `Device`, so a device cannot be closed under
a request. The `IORequest` layout, including the difference of `timerequest`
between the two ABIs, never leaves the native bridge. Two request shapes exist:
standard (`IOStdReq`, with up to 64 KiB of data) and timer (`timerequest`). A
device error is reported in the `IoOutcome`, not as an `Err`.

## Worked examples

The examples below are complete functions. Each takes the `Context` your entry function receives and returns an `aros::Error` on failure, so `?` works throughout. Every one of them is compiled for both targets by the repository's example check.

### Copy a file to standard output

```rust
use aros::{BytePath, Context, Error, File, FileMode, Stdout};

fn copy_to_stdout(context: &Context, path: &[u8]) -> Result<(), Error> {
    let path = BytePath::new(path)?;
    let mut file = File::open(context, &path, FileMode::ReadExisting)?;
    let mut out = Stdout::new(context)?;
    let mut buffer = [0u8; 4096];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break; // end of file
        }
        out.write_all(&buffer[..read])?;
    }
    file.close()
}
```

`File::read` may return fewer bytes than the buffer holds, so the loop continues until it returns zero. `write_all` retries short writes. The explicit `close` reports a native close error; dropping the file would have closed it silently.

### Classify a failure

```rust
use aros::{BytePath, Context, Error, ErrorKind, File, FileMode};

fn exists(context: &Context, path: &[u8]) -> Result<bool, Error> {
    let path = BytePath::new(path)?;
    match File::open(context, &path, FileMode::ReadExisting) {
        Ok(file) => {
            file.close()?;
            Ok(true)
        }
        // DOS could not open it; `error.native` holds the DOS error code.
        Err(error) if error.kind == ErrorKind::Native => Ok(false),
        Err(other) => Err(other),
    }
}
```

### Send a message between private ports

```rust
use aros::{Context, Error, Message, Port};

fn ping(context: &Context) -> Result<(), Error> {
    let port = Port::new(context)?;
    let reply = Port::new(context)?;
    let mut message = Message::new(context, b"ping")?;

    port.send(&mut message, &reply)?;
    assert!(port.receive(&mut message)?);

    let mut payload = [0u8; 4];
    let length = message.copy_to(&mut payload)?;
    assert_eq!(&payload[..length], b"ping");
    message.reply()
}
```

Ports are private to your application and at most two exist at once. `receive` checks that the message you pass is at the head of the queue; it does not search past another message.

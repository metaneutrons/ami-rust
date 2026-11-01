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

`File` provides `read`, `write`, `read_exact`, `write_all`, `seek` (with
`SeekFrom`), `position`, `len` and consuming `close`. Single reads and writes may make partial progress; the `*_exact` and
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

## Directories, variables and arguments

| Item | Use |
| --- | --- |
| `Dir::open(context, path)` | Opens a directory; it is an `Iterator` of `Result<Entry, Error>`, or call `next_entry`. |
| `Entry` | Name (bytes), `is_dir`, `is_file`, `size`, `protection`, `modified`, raw `entry_type`. |
| `metadata(context, path)` | The `Entry` of one path. |
| `create_dir`, `delete`, `rename` | Create a directory, delete a file or empty directory, rename or move within a volume. |
| `current_dir`, `set_current_dir` | Read or change the task's current directory; the change is undone when the program ends. |
| `var`, `set_var`, `delete_var` with `VarScope` | Local (per process) and global (`ENV:`) variables, `Any` looking at local ones first. |
| `Template::parse(spec)` and `Template::read(args)` | Match the program's arguments against a `ReadArgs` template; see below. |

Names and values are byte strings. The protection bits follow DOS: the low
four (delete, execute, write and read) are set when the action is *denied*, and
the `FIBB_HOLD` bit exists only on ABI-v1.
Every lock the bridge takes is released, also for a `Dir` that is forgotten, and
a changed current directory is restored when the program ends. A variable value
is at most 4096 bytes and cannot contain a NUL byte; a value that does not fit
the buffer of `var` is a native error (`ERROR_BUFFER_OVERFLOW`, 303) rather than
a truncated string.

### Argument templates

`Template` follows `ReadArgs`: `FROM/A/M,TO/K,ALL/S,COUNT/N` has a required
list of values, a keyword-only value, a switch and a number. The modifiers are
`/A` required, `/K` keyword required, `/S` switch, `/T` toggle (parsed like a
switch), `/N` number, `/M` any number of values and `/F` the rest of the line.
Keywords match ignoring case and may have an alias, `QUIET=Q/S`. A keyword is
written `KEY value` or `KEY=value`, and every `=` separates arguments as in
`ReadArgs`. A `/M` item leaves the last arguments to the required items after
it, and a keyword before a `/M` item gives it exactly one value.

The parser is checked against the real dos.library `ReadArgs` on both ABIs: the
qualification fixture runs 62 argument lists through both and requires the same
result. It differs in documented ways. A `/N` value outside `i32` is an error
(`ReadArgs` wraps it around). Quoting is gone once the C start-up has split the
arguments, so an argument that contains `=` cannot be kept whole; read it from
`Context::args` instead. The prompting `?` form is not supported. A `/F` item's
rest of the line is read back with `Values::write_line`.

## Large files

Sizes and positions are 64-bit in the API, but what the system can deliver
depends on the ABI and the volume.

| Case | Entry size | `File::len`, `position`, `seek` |
| --- | --- | --- |
| ABI-v1 with `dos64.library` (the qualified image has it) | 64-bit; `size_is_exact()` is true | 64-bit. A volume whose handler lacks 64-bit support can still refuse a position above 2 GiB; observed with FAT: `ERROR_OBJECT_TOO_LARGE` (207). |
| ABI-v11 (the pinned Deadwood tree has no `dos64`), or ABI-v1 without the library | The 32-bit value read as unsigned; `size_is_exact()` is false at or above 2 GiB | A size, position or offset that does not fit the 32-bit calls is `ErrorKind::Limit` instead of a wrapped value. |

`Entry::size_is_exact` is conservative. On a FAT volume the pinned handler
reports a 3 GiB file correctly through the 32-bit path (as an unsigned value, up
to 4 GiB minus one), but `size_is_exact` is still false there because the
32-bit path cannot tell a correct large value from a capped one. Observed
on the qualified images, in QEMU, with a FAT32 volume holding a 3 GiB file:

| Call | ABI-v1 | ABI-v11 |
| --- | --- | --- |
| `metadata` size | 3,221,225,472, exact | 3,221,225,472, not exact |
| `File::len` | 3,221,225,472 | `Limit` |
| `seek(End(0))`, `position` | 3,221,225,472 | `Limit` |
| `seek(Start(3 GiB - 4))` | `ERROR_OBJECT_TOO_LARGE` (the handler is 32-bit) | `Limit` |

Writing above 2 GiB needs a volume whose handler is 64-bit, which among the
pinned handlers is PFS3. A PFS3 partition crashes the pinned ABI-v1 image while
it boots (every RDB image with a PFS3 partition, formatted or not, did; a FAT
partition and an FFS partition did not; the cause is a handler that calls libc
before its library base is set, [AROS-NX issue 121](https://github.com/metaneutrons/AROS-NX/issues/121)),
so writes above 2 GiB are not verified.

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

### List a directory

```rust
use aros::{BytePath, Context, Dir, Error, Stdout, Template};

fn decimal(mut number: u64, buffer: &mut [u8; 20]) -> &[u8] {
    let mut at = buffer.len();
    loop {
        at -= 1;
        buffer[at] = b'0' + (number % 10) as u8;
        number /= 10;
        if number == 0 {
            return &buffer[at..];
        }
    }
}

fn list(context: &Context) -> Result<(), Error> {
    // DIR is the directory to list, ALL also prints sizes.
    let Ok(template) = Template::parse(b"DIR,ALL/S") else {
        return Ok(());
    };
    let Ok(values) = template.read(context.args().skip(1)) else {
        return Ok(());
    };
    let path = BytePath::new(values.text(0).unwrap_or(b"RAM:"))?;
    let mut out = Stdout::new(context)?;
    for entry in Dir::open(context, &path)? {
        let entry = entry?;
        out.write_all(entry.name())?;
        if entry.is_dir() {
            out.write_all(b"/")?;
        } else if values.switch(1) {
            out.write_all(b" ")?;
            out.write_all(decimal(entry.size(), &mut [0u8; 20]))?;
        }
        out.write_all(b"\n")?;
    }
    Ok(())
}
```

Opening can fail with a native error such as `ERROR_OBJECT_NOT_FOUND` (205) or,
for a file, `ERROR_OBJECT_WRONG_TYPE` (212); the `Dir` handle releases its lock
when it is dropped.

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

---
title: API, lifetimes, and failures
---

# API, lifetimes, and failures

`ami-rust` has two public, safe-facing crates: `aros` for AROS applications
and `aros-mui` for MUI applications. Both target x86-64 AROS ABI-v1 and ABI-v11.
They are `no_std` APIs and are intentionally task-affine: a native AROS handle
belongs to the application task and cannot be sent to another task.

For dependency configuration and target selection, see the
[consumer guide](https://ami-rust.metaneutrons.cc/consumer-guide/). The
[generated Rust API reference](https://ami-rust.metaneutrons.cc/rust-api/)
contains the complete item-level documentation.

## `aros`: application runtime and core services

An application uses one `entry!` macro invocation and a function with the
following shape:

```rust
fn application(context: &aros::Context) -> aros::AppStatus {
    let _ = context;
    aros::AppStatus::Success
}

aros::entry!(application);
```

`entry!(application, alloc)` additionally installs `ExecAllocator`. Native
allocation can still fail. Use fallible collection APIs where an allocation
failure is recoverable; Rust's infallible allocation path terminates through
the native fatal path rather than unwinding through C.

`Context` is supplied by the runtime and is valid only for the entry function.
It provides borrowed argument bytes, bounded diagnostics, and a resource
statistics snapshot. Handles created from it borrow the same context:

| Surface | Public API and contract |
| --- | --- |
| Files | `BytePath` rejects embedded NUL bytes. `File` has explicit read, truncate/create, and read/write modes. Reads and writes use caller-owned buffers and may complete partially. |
| Standard output | `Stdout` and `Stderr` borrow DOS process handles; they never close those handles. `Stderr` uses the process error handle and falls back to standard output if necessary. |
| Libraries | `Library::open` returns an owned reference that is released by `close` or `Drop`. Minimum library versions are explicit. |
| Signals | `Signal` allocates one task-local signal bit and releases it when dropped. A signal can be posted and waited from its creating task. |
| Ports and messages | `Port` and `Message` are local, task-bound values. A message has an explicit reply route; `receive` checks a supplied message rather than draining arbitrary queue entries. |
| Callback | `call` invokes a callback synchronously. The callback frame is never retained by the native side. |

Errors are allocation-free `aros::Error` values. Their `ErrorKind` separates
invalid input, native operation failure, a documented API limit, wrong owner,
invalid state, end of file, and zero progress. A failed operation does not imply
that a resource was closed or consumed unless its individual method documents
that transfer.

## `aros-mui`: typed MUI ownership

Open MUI against the active context, then create a scope. A scope owns native
roots, retained strings, hooks, and custom-class registrations. Typed object
handles are copyable views into that scope; copying one never duplicates or
disposes a native object.

```rust
let mui = aros_mui::Mui::open(context)?;
mui.scope(|scope| {
    let text = scope.builder::<aros_mui::classes::Text>().build()?;
    let _ = text;
    Ok::<(), aros_mui::Error>(())
})?;
```

Builders accept generated construction attributes. `Object::set`, `get`, and
`call` use generated, class-checked descriptors; `adopt` records native child
ownership only between compatible classes in the same scope. Cross-scope
objects, ownership cycles, duplicate attachment, and a second window root are
rejected before a native call.

Notifications connect typed readable attributes to an application return ID, a
typed no-notify set, or a scope-retained hook. Hooks and custom classes are
valid for the scope only. Raw MUI messages, foreign pointers, and contracts
whose native retention cannot be proven remain explicit unsafe operations.

The ordinary API is `aros-mui`; `aros-mui-sys` is intentionally not a consumer
reference surface. It contains the raw ABI declarations used to implement and
audit the safe layer.

## ABI scope

The target triple selects the ABI:

- `x86_64-unknown-aros-abi1`
- `x86_64-unknown-aros-abi11`

Application source does not select an ABI with a Cargo feature. The public API
does not promise compatibility with other AROS architectures, full `std`, or a
native AROS-hosted Rust compiler. Those boundaries are described in the
[compatibility profile](https://ami-rust.metaneutrons.cc/compatibility/).

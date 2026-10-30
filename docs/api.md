---
title: Programming model
description: The ownership, lifetime and failure rules shared by the aros and aros-mui crates.
---

`aros` and `aros-mui` are `no_std` libraries built around one idea: **an AROS resource belongs to the task that created it, and Rust's types make that visible.** This page explains the rules that apply to every handle. The per-crate guides ([`aros`](/api/aros/), [`aros-mui`](/api/aros-mui/)) cover each type, and the [API reference](/reference/) lists every item.

## The `Context` is a witness

The native runtime starts your program, claims one owner task and calls your entry function with a `&Context`. The `Context` carries no resource. It proves that you are on the application task, inside the live entry frame. Every safe handle is created from it and borrows it:

```rust
fn application(context: &aros::Context) -> aros::AppStatus {
    // File::open, Stdout::new, Port::new, Mui::open ... all take `context`.
    aros::AppStatus::Success
}
```

Because handles borrow the `Context`, none of them can outlive the entry function. Because the `Context` is neither `Send` nor `Sync`, none of them can move to another task. The compiler enforces both rules, so there are no run-time checks to remember.

## Ownership and cleanup

- A handle owns its native resource and releases it when dropped.
- Types that can fail on release also offer an explicit `close(self)`. Use it when you need to observe the error; `Drop` closes on a best-effort basis and cannot report one. `close` consumes the handle even when it fails, so there is nothing to retry.
- When your entry function returns, the runtime releases every tracked resource, **including handles whose Rust owners were forgotten** with `mem::forget` or leaked.
- `Context::statistics()` gives a snapshot of the native resource counters, which is a cheap way to assert in a test that a code path released everything.

For MUI the unit of ownership is the **scope**. `Mui::scope` runs a closure with a fresh `Scope` that owns every native object, string array, hook and custom-class registration created through it. Objects are copyable *views* into that storage. Copying one never duplicates or disposes anything. Parents dispose their adopted children, and the scope disposes whatever remains.

## Bounded resources

The SDK keeps small fixed registries instead of growing without limit: 16 open files, 4 optional libraries, 2 private ports, 4 signal slots, and 8 messages of at most 256 bytes. A path is at most 127 bytes and a single file or stream transfer at most 64 KiB. Exceeding a bound returns `ErrorKind::Limit` rather than failing later. These are API limits, not a memory quota; Exec allocation can still fail. The [`aros` guide](/api/aros/#errors-and-bounds) has the table.

## Errors

Every fallible operation returns `Result<_, aros::Error>` (or `aros_mui::Error` for MUI). The `aros::Error` is a small `Copy` record with no allocation:

| Field | Meaning |
| --- | --- |
| `kind` | The class of failure: native failure, invalid input, a documented limit, wrong task owner, invalid state, end of file or zero progress. |
| `operation` | Which SDK operation failed. |
| `native` | The native code, such as the DOS error, or zero for checks made locally. |

A failed operation does not imply that a resource was closed or consumed. Each method documents whether it takes ownership on failure (`close` always does). Short reads and writes are normal: `File::read` and `File::write` may transfer less than requested, and `read_exact` and `write_all` loop until done or until an error.

`aros_mui::Error` wraps `aros::Error` unchanged as `Error::Aros`, and adds the ownership and scope violations that MUI objects can hit. Those are detected before any native call is made.

## Panics and allocation failure

A panic does not unwind into AROS. The runtime installs a heap-free panic handler that enters the native fatal path, and the program ends with `AppStatus::Fatal` (return code 20). Rust's infallible allocation APIs terminate through that same path when the allocator refuses; they do not return an `aros::Error`. Where an allocation failure is recoverable, prefer fallible collection APIs.

## The raw boundary

Everything that the type system cannot prove stays behind an explicit `unsafe` item with a documented contract: `Library::raw_base`, `Object::call_raw`, `Object::set_raw` and `get_raw`, `ForeignPtr`, and the whole `aros-sys` and `aros-mui-sys` crates. Ordinary applications should not need them. When you do, document the pointer, lifetime and retention contract you are relying on.

## ABI and target

The AROS ABI is chosen by the Cargo target. The programming model above is the same on both; see [targets and ABIs](/targets-and-abis/) and the generated list of the [few items](/reference/abi-differences/) that exist on only one.
